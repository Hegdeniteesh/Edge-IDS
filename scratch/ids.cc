#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/csma-module.h"
#include "ns3/applications-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("BotIoTTrafficSimulation_NoDDoS_Eth_PCAP");

int main(int argc, char* argv[])
{
    // Link configs
    std::string ethRate   = "1Gbps";   // Ethernet link Node0<->Node1 (victim capture)
    std::string ethDelay  = "1ms";
    std::string p2pRate   = "100Mbps"; // for Node2<->Node3 (normal)
    std::string p2pDelay  = "2ms";
    std::string pcapPrefix = "botiot-aligned-traffic"; // final file like botiot-aligned-traffic-1-0.pcap

    // Normal (UDP Node2->Node3)
    double normalStartTime = 1.0;
    double normalDuration  = 60.0;
    std::string normalDataRate = "1Mbps";
    uint32_t normalPacketSize  = 512;
    uint16_t normalPort        = 80;

    // DoS window (TCP Node0->Node1:443) as many short, low-byte flows
    double dosStartTime = 30.0;
    double dosDuration  = 60.0;   // 30–90s
    uint16_t dosPort    = 443;

    // Per-connection DoS shape: ~10 pkts, few KB, ~5s each
    uint32_t dosConns        = 200;       // number of short connections
    double   dosConnLength   = 5.0;       // seconds
    std::string dosConnRate  = "5Kbps";   // ~2 pps with 300B, ~10 packets in 5s
    uint32_t dosPacketSize   = 300;

    // Recon (tiny UDP scans Node0->Node1)
    double reconStartTime    = 50.0;
    uint32_t numPortsToScan  = 80;
    uint16_t reconPortStart  = 1000;
    std::string reconDataRate = "64Kbps";
    uint32_t reconPacketSize  = 60;
    double perPortBurst       = 0.02;  // 20 ms per port
    double portSpacing        = 0.03;  // 30 ms between ports

    // Theft (TCP Node0->Node1:21), several low-pps parallel flows
    double theftStartTime = 70.0;
    double theftDuration  = 60.0;    // 70–130s
    uint16_t theftPort    = 21;
    uint32_t theftFlows   = 6;       // number of parallel exfil flows
    std::string theftPerFlowRate = "160Kbps"; // ~11 pps @ 1450B (<20 pps)
    uint32_t theftPacketSize     = 1450;     // larger packets, sustained

    CommandLine cmd(__FILE__);
    cmd.AddValue("pcapPrefix",   "PCAP file prefix (no .pcap)", pcapPrefix);
    cmd.AddValue("dosStart",     "DoS start time", dosStartTime);
    cmd.AddValue("dosDuration",  "DoS duration", dosDuration);
    cmd.AddValue("reconStart",   "Recon start time", reconStartTime);
    cmd.AddValue("theftStart",   "Theft start time", theftStartTime);
    cmd.AddValue("theftDuration","Theft duration", theftDuration);
    cmd.Parse(argc, argv);

    LogComponentEnable("BotIoTTrafficSimulation_NoDDoS_Eth_PCAP", LOG_LEVEL_INFO);

    // Nodes: 0=Attacker, 1=Victim, 2=Normal Client, 3=Normal Server
    NodeContainer nodes; nodes.Create(4);

    // Ethernet link: Node0 <-> Node1 (victim capture)
    CsmaHelper csma;
    csma.SetChannelAttribute("DataRate", StringValue(ethRate));
    csma.SetChannelAttribute("Delay",    StringValue(ethDelay));
    NodeContainer pair01(nodes.Get(0), nodes.Get(1));
    NetDeviceContainer dev01 = csma.Install(pair01);

    // Point-to-point link: Node2 <-> Node3 (normal)
    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue(p2pRate));
    p2p.SetChannelAttribute("Delay",   StringValue(p2pDelay));
    NetDeviceContainer dev23 = p2p.Install(NodeContainer(nodes.Get(2), nodes.Get(3)));

    // Internet + IPs
    InternetStackHelper stack; stack.Install(nodes);
    Ipv4AddressHelper address;

    address.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer if01 = address.Assign(dev01);

    address.SetBase("10.1.2.0", "255.255.255.0");
    Ipv4InterfaceContainer if23 = address.Assign(dev23);

    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    // Normal (UDP Node2 -> Node3)
    NS_LOG_INFO("Normal UDP Node2->Node3...");
    {
        PacketSinkHelper sink("ns3::UdpSocketFactory",
                              InetSocketAddress(Ipv4Address::GetAny(), normalPort));
        auto appsSink = sink.Install(nodes.Get(3));
        appsSink.Start(Seconds(normalStartTime));
        appsSink.Stop(Seconds(normalStartTime + normalDuration));

        OnOffHelper client("ns3::UdpSocketFactory",
                           InetSocketAddress(if23.GetAddress(1), normalPort));
        client.SetAttribute("OnTime",     StringValue("ns3::ConstantRandomVariable[Constant=1]"));
        client.SetAttribute("OffTime",    StringValue("ns3::ConstantRandomVariable[Constant=0.1]"));
        client.SetAttribute("DataRate",   StringValue(normalDataRate));
        client.SetAttribute("PacketSize", UintegerValue(normalPacketSize));

        auto appsClient = client.Install(nodes.Get(2));
        appsClient.Start(Seconds(normalStartTime));
        appsClient.Stop(Seconds(normalStartTime + normalDuration));
    }

    // DoS (TCP Node0 -> Node1:443) as many short, low-byte flows
    NS_LOG_INFO("DoS TCP Node0->Node1:443 as many short low-byte flows...");
    {
        PacketSinkHelper sink("ns3::TcpSocketFactory",
                              InetSocketAddress(Ipv4Address::GetAny(), dosPort));
        auto appsSink = sink.Install(nodes.Get(1));
        appsSink.Start(Seconds(dosStartTime));
        appsSink.Stop(Seconds(dosStartTime + dosDuration + 2.0));

        for (uint32_t i = 0; i < dosConns; ++i) {
            double frac   = (dosConns > 1) ? (double)i / (double)(dosConns - 1) : 0.0;
            double start  = dosStartTime + frac * (dosDuration - dosConnLength);
            double stop   = start + dosConnLength;

            OnOffHelper dos("ns3::TcpSocketFactory",
                            InetSocketAddress(if01.GetAddress(1), dosPort));
            dos.SetAttribute("OnTime",     StringValue("ns3::ConstantRandomVariable[Constant=1]"));
            dos.SetAttribute("OffTime",    StringValue("ns3::ConstantRandomVariable[Constant=0]"));
            dos.SetAttribute("DataRate",   StringValue(dosConnRate));     // 5 Kbps
            dos.SetAttribute("PacketSize", UintegerValue(dosPacketSize)); // 300B

            auto app = dos.Install(nodes.Get(0));
            app.Start(Seconds(start));
            app.Stop(Seconds(stop));
        }
    }

    // Recon (tiny UDP scans Node0 -> Node1)
    NS_LOG_INFO("Recon UDP tiny scans Node0->Node1...");
    for (uint32_t i = 0; i < numPortsToScan; ++i)
    {
        uint16_t port = reconPortStart + i;
        double t = reconStartTime + i * portSpacing;

        PacketSinkHelper sink("ns3::UdpSocketFactory",
                              InetSocketAddress(Ipv4Address::GetAny(), port));
        auto appsSink = sink.Install(nodes.Get(1));
        appsSink.Start(Seconds(t));
        appsSink.Stop(Seconds(t + perPortBurst + 0.1));

        OnOffHelper scanner("ns3::UdpSocketFactory",
                            InetSocketAddress(if01.GetAddress(1), port));
        scanner.SetAttribute("OnTime",     StringValue("ns3::ConstantRandomVariable[Constant=0.004]"));
        scanner.SetAttribute("OffTime",    StringValue("ns3::ConstantRandomVariable[Constant=0.0]"));
        scanner.SetAttribute("DataRate",   StringValue(reconDataRate));
        scanner.SetAttribute("PacketSize", UintegerValue(reconPacketSize));

        auto apps = scanner.Install(nodes.Get(0));
        apps.Start(Seconds(t));
        apps.Stop(Seconds(t + perPortBurst));
    }

    // Theft (TCP Node0 -> Node1:21) as several parallel, low-pps flows
    NS_LOG_INFO("Theft TCP Node0->Node1:21 sustained parallel low-pps flows...");
    {
        PacketSinkHelper sink("ns3::TcpSocketFactory",
                              InetSocketAddress(Ipv4Address::GetAny(), theftPort));
        auto appsSink = sink.Install(nodes.Get(1));
        appsSink.Start(Seconds(theftStartTime));
        appsSink.Stop(Seconds(theftStartTime + theftDuration + 2.0));

        for (uint32_t i = 0; i < theftFlows; ++i) {
            double start = theftStartTime + i * 1.5; // slight staggering
            double stop  = theftStartTime + theftDuration;

            OnOffHelper exfil("ns3::TcpSocketFactory",
                              InetSocketAddress(if01.GetAddress(1), theftPort));
            exfil.SetAttribute("OnTime",     StringValue("ns3::ConstantRandomVariable[Constant=1]"));
            exfil.SetAttribute("OffTime",    StringValue("ns3::ConstantRandomVariable[Constant=0]"));
            exfil.SetAttribute("DataRate",   StringValue(theftPerFlowRate));   // ~11 pps
            exfil.SetAttribute("PacketSize", UintegerValue(theftPacketSize));  // 1450B

            auto app = exfil.Install(nodes.Get(0));
            app.Start(Seconds(start));
            app.Stop(Seconds(stop));
        }
    }

    // Single Ethernet PCAP on the victim side of Node0<->Node1
    NS_LOG_INFO("Enabling victim-side Ethernet PCAP...");
    csma.EnablePcap(pcapPrefix, dev01.Get(1), true); // -> botiot-aligned-traffic-1-0.pcap

    Simulator::Stop(Seconds(180.0));
    Simulator::Run();
    Simulator::Destroy();
    return 0;
}