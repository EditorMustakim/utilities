// freeip - finds free IPv4 addresses on a local subnet (ping sweep + live ARP probe)
//
// Usage:
//   freeip 172.25.155.33/27
//   freeip                       (auto-detects your subnet)
//   freeip 172.25.155.0/27 -p 3 -t 2000 -csv free.csv
//
// Options:
//   -p <n>      number of ping passes (default 2)
//   -t <ms>     ping timeout in milliseconds (default 1000)
//   -csv <file> save the free list to a CSV file

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

class FreeIp
{
    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    static extern int SendARP(uint destIp, uint srcIp, byte[] mac, ref int macLen);

    class Row
    {
        public uint Num;
        public string Ip;
        public string How;
        public string Mac;
        public string Note;
    }

    static uint ToNum(IPAddress ip)
    {
        byte[] b = ip.GetAddressBytes();
        return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | (uint)b[3];
    }

    static IPAddress ToIp(uint n)
    {
        return new IPAddress(new byte[] { (byte)(n >> 24), (byte)(n >> 16), (byte)(n >> 8), (byte)n });
    }

    static void Usage()
    {
        Console.WriteLine("freeip - find free IPv4 addresses on a local subnet");
        Console.WriteLine();
        Console.WriteLine("Usage:  freeip [subnet/prefix] [-p passes] [-t timeoutMs] [-csv file]");
        Console.WriteLine("Example: freeip 172.25.155.33/27");
        Console.WriteLine("With no subnet, the subnet of your default-gateway adapter is used.");
        Console.WriteLine("Supported prefix lengths: /22 to /30");
    }

    static int Main(string[] args)
    {
        // A freshly opened console (double-click) starts with the cursor at 0,0.
        bool pause = false;
        try
        {
            if (!Console.IsOutputRedirected && Console.CursorLeft == 0 && Console.CursorTop == 0)
                pause = true;
        }
        catch { }

        int code = 0;
        try { code = Run(args); }
        catch (Exception ex)
        {
            Console.Error.WriteLine("Error: " + ex.Message);
            code = 1;
        }

        if (pause)
        {
            Console.WriteLine();
            Console.WriteLine("Press any key to exit...");
            Console.ReadKey(true);
        }
        return code;
    }

    static int Run(string[] args)
    {
        string subnet = null;
        int timeout = 1000;
        int passes = 2;
        string csv = null;

        for (int i = 0; i < args.Length; i++)
        {
            string a = args[i];
            if (a == "-h" || a == "--help" || a == "/?") { Usage(); return 0; }
            else if (a == "-t" && i + 1 < args.Length) timeout = int.Parse(args[++i]);
            else if (a == "-p" && i + 1 < args.Length) passes = int.Parse(args[++i]);
            else if (a == "-csv" && i + 1 < args.Length) csv = args[++i];
            else subnet = a;
        }

        // ---- Local addresses and gateways ----
        HashSet<uint> localIps = new HashSet<uint>();
        HashSet<uint> gateways = new HashSet<uint>();
        string autoSubnet = null;

        foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up) continue;
            IPInterfaceProperties props = nic.GetIPProperties();

            bool hasGateway = false;
            foreach (GatewayIPAddressInformation g in props.GatewayAddresses)
            {
                if (g.Address.AddressFamily == AddressFamily.InterNetwork && !g.Address.Equals(IPAddress.Any))
                {
                    gateways.Add(ToNum(g.Address));
                    hasGateway = true;
                }
            }

            foreach (UnicastIPAddressInformation u in props.UnicastAddresses)
            {
                if (u.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                localIps.Add(ToNum(u.Address));
                if (hasGateway && autoSubnet == null)
                    autoSubnet = u.Address.ToString() + "/" + u.PrefixLength;
            }
        }

        if (subnet == null)
        {
            if (autoSubnet == null)
                throw new Exception("Could not auto-detect a subnet. Pass one, e.g. freeip 172.25.155.33/27");
            subnet = autoSubnet;
        }

        // ---- Work out the subnet ----
        string[] parts = subnet.Split('/');
        if (parts.Length != 2) throw new Exception("Use CIDR format, e.g. 172.25.155.33/27");
        IPAddress ip;
        if (!IPAddress.TryParse(parts[0], out ip) || ip.AddressFamily != AddressFamily.InterNetwork)
            throw new Exception("Invalid IPv4 address: " + parts[0]);
        int prefix;
        if (!int.TryParse(parts[1], out prefix) || prefix < 22 || prefix > 30)
            throw new Exception("Prefix must be between /22 and /30.");

        uint size = 1u << (32 - prefix);
        uint ipNum = ToNum(ip);
        uint net = ipNum - (ipNum % size);
        uint bcast = net + size - 1;
        uint first = net + 1;
        uint last = bcast - 1;

        List<uint> hosts = new List<uint>();
        for (uint n = first; n <= last; n++) hosts.Add(n);

        Console.WriteLine();
        Console.WriteLine("Subnet    : {0}/{1}", ToIp(net), prefix);
        Console.WriteLine("Usable    : {0} - {1}  ({2} addresses)", ToIp(first), ToIp(last), hosts.Count);
        Console.WriteLine("Broadcast : {0}", ToIp(bcast));

        bool isLocalSubnet = localIps.Any(l => l >= net && l <= bcast);
        if (!isLocalSubnet)
        {
            Console.WriteLine();
            Console.WriteLine("Warning: this PC is not on that subnet, so the ARP probe is skipped");
            Console.WriteLine("(it would return the router's MAC for every address). Only ping is used,");
            Console.WriteLine("so hosts that block ping will wrongly look free.");
        }

        // ---- Ping sweep (all hosts in parallel, repeated) ----
        HashSet<uint> pingReplied = new HashSet<uint>();
        for (int p = 1; p <= passes; p++)
        {
            Console.WriteLine("Ping sweep pass {0} of {1} ...", p, passes);
            Dictionary<uint, Task<PingReply>> tasks = new Dictionary<uint, Task<PingReply>>();
            List<Ping> pingers = new List<Ping>();

            foreach (uint h in hosts)
            {
                try
                {
                    Ping pinger = new Ping();
                    pingers.Add(pinger);
                    tasks[h] = pinger.SendPingAsync(ToIp(h), timeout);
                }
                catch { }
            }

            foreach (KeyValuePair<uint, Task<PingReply>> kv in tasks)
            {
                try
                {
                    PingReply r = kv.Value.Result;
                    if (r.Status == IPStatus.Success) pingReplied.Add(kv.Key);
                }
                catch { }
            }

            foreach (Ping pinger in pingers) pinger.Dispose();
        }

        // ---- ARP probe (asks each address directly on the local segment) ----
        Dictionary<uint, string> arp = new Dictionary<uint, string>();
        if (isLocalSubnet)
        {
            Console.WriteLine("ARP probe ...");
            ThreadPool.SetMinThreads(64, 64);
            object lk = new object();
            ParallelOptions opts = new ParallelOptions();
            opts.MaxDegreeOfParallelism = 64;

            Parallel.ForEach(hosts, opts, delegate(uint h)
            {
                byte[] mac = new byte[6];
                int len = 6;
                uint dest = BitConverter.ToUInt32(ToIp(h).GetAddressBytes(), 0);
                int rc = SendARP(dest, 0, mac, ref len);
                if (rc == 0 && len == 6)
                {
                    string m = BitConverter.ToString(mac).ToLower();
                    if (m != "00-00-00-00-00-00")
                    {
                        lock (lk) { arp[h] = m; }
                    }
                }
            });
        }

        // ---- Classify ----
        List<Row> taken = new List<Row>();
        List<uint> free = new List<uint>();

        foreach (uint h in hosts)
        {
            bool byPing = pingReplied.Contains(h);
            bool byArp = arp.ContainsKey(h);
            bool isMe = localIps.Contains(h);

            if (byPing || byArp || isMe)
            {
                List<string> how = new List<string>();
                if (isMe) how.Add("this PC");
                if (byPing) how.Add("ping");
                if (byArp) how.Add("ARP");

                string note = "";
                if (gateways.Contains(h)) note = "default gateway";
                else if (byArp && !byPing && !isMe) note = "live, blocks ping";

                Row row = new Row();
                row.Num = h;
                row.Ip = ToIp(h).ToString();
                row.How = string.Join("+", how.ToArray());
                row.Mac = byArp ? arp[h] : "";
                row.Note = note;
                taken.Add(row);
            }
            else
            {
                free.Add(h);
            }
        }

        // ---- Report ----
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("TAKEN ({0}):", taken.Count);
        Console.ResetColor();
        Console.WriteLine("{0,-16} {1,-16} {2,-18} {3}", "IP", "Detected", "MAC", "Note");
        foreach (Row r in taken)
            Console.WriteLine("{0,-16} {1,-16} {2,-18} {3}", r.Ip, r.How, r.Mac, r.Note);

        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("FREE CANDIDATES ({0}):", free.Count);
        Console.ResetColor();
        Console.WriteLine(string.Join(", ", free.Select(f => ToIp(f).ToString()).ToArray()));

        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("Free ranges:");
        Console.ResetColor();
        if (free.Count > 0)
        {
            uint s = free[0], pv = free[0];
            for (int i = 1; i <= free.Count; i++)
            {
                if (i < free.Count && free[i] == pv + 1) { pv = free[i]; continue; }
                uint len = pv - s + 1;
                if (len == 1) Console.WriteLine("  {0}", ToIp(s));
                else Console.WriteLine("  {0} - {1}   ({2} addresses)", ToIp(s), ToIp(pv), len);
                if (i < free.Count) { s = free[i]; pv = free[i]; }
            }
        }

        Console.WriteLine();
        Console.WriteLine("Note: 'free' means no ping reply and no ARP answer right now. Devices that");
        Console.WriteLine("are off, asleep, or in a DHCP pool can still claim these. Check with whoever");
        Console.WriteLine("runs the network, and re-run at a different time of day before assigning one.");

        if (csv != null)
        {
            using (StreamWriter w = new StreamWriter(csv))
            {
                w.WriteLine("FreeIP");
                foreach (uint f in free) w.WriteLine(ToIp(f));
            }
            Console.WriteLine("Saved free list to " + csv);
        }

        return 0;
    }
}
