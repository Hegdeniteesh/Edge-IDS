#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/csma-module.h"
#include "ns3/applications-module.h"
#include "ns3/ipv4-static-routing-helper.h"
#include "ns3/ipv4-list-routing-helper.h"
#include <fstream>
#include <sstream>
#include <nlohmann/json.hpp>

using namespace ns3;
NS_LOG_COMPONENT_DEFINE("BotIoTTrafficSimulation_NoDDoS_Eth_PCAP_Enhanced");

// Global variables for IPC
std::string g_command_file = "nids_commands.json";
std::string g_event_file = "nids_events.json";
bool g_rerouting_enabled = true; // Can be made configurable

// Helper function to read the latest command from Python
bool ReadCommand(std::map<std::string, std::string>& command) {
    if (!std::ifstream(g_command_file).good()) {
        return false;
    }
    try {
        std::ifstream f(g_command_file);
        nlohmann::json j;
        f >> j;
        // Clear the command file after reading
        std::ofstream clear_file(g_command_file, std::ios::trunc);
        clear_file.close();
        // Extract fields
        command["src_ip"] = j.value("src_ip", "");
        command["dst_ip"] = j.value("dst_ip", "");
        command["attack_type"] = j.value("attack_type", "");
        command["action"] = j.value("action", "");
        return true;
    } catch (const std::exception& e) {
        NS_LOG_ERROR("Failed to read command: " << e.what());
        return false;
    }
}

// Helper function to write an event back to Python
void WriteEvent(const std::string& type, const std::string& message) {
    try {
        nlohmann::json event;
        event["type"] = type;
        event["message"] = message;

        std::vector<nlohmann::json> events;

        // Read existing events if any
        if (std::ifstream(g_event_file).good()) {
            std::ifstream f(g_event_file);
            nlohmann::json j;
            f >> j; // Read entire JSON (should be an array)
            if (j.is_array()) {
                // Convert json array to vector<json>
                events = j.get<std::vector<nlohmann::json>>();
            }
            // If it's not an array, we'll overwrite it with a new array
        }

        events.push_back(event);

        // Write back the entire vector as a JSON array
        std::ofstream f_out(g_event_file);
        f_out << std::setw(4) << events << std::endl;

    } catch (const std::exception& e) {
        NS_LOG_ERROR("Failed to write event: " << e.what());
    }
}

// Function to dynamically reroute traffic on Node 0 (Router)
void DynamicReroute(Ptr<Node> routerNode, const std::string& dstIp, const std::string& action) {
    if (!g_rerouting_enabled) {
        return;
    }
    Ptr<Ipv4> ipv4 = routerNode->GetObject<Ipv4>();
    if (!ipv4) {
        NS_LOG_ERROR("Router node has no Ipv4 object.");
        return;
    }
    Ptr<Ipv4StaticRouting> staticRouting = ipv4->GetRoutingProtocol()->GetObject<Ipv4StaticRouting>();
    if (!staticRouting) {
        NS_LOG_ERROR("Could not get static routing protocol.");
        return;
    }
    std::string nextHop = "0.0.0.0";
    if (action.find("Sinkhole") != std::string::npos) {
        nextHop = "10.1.3.2"; // IP of Sinkhole node
    } else if (action.find("Honeypot") != std::string::npos) {
        nextHop = "10.1.4.2"; // IP of Honeypot node
    } else {
        NS_LOG_INFO("No rerouting action taken for: " << action);
        return;
    }
    // Add/Modify the route for the destination IP
    staticRouting->AddHostRouteTo(Ipv4Address(dstIp.c_str()), Ipv4Address(nextHop.c_str()), 1);
    NS_LOG_INFO("Rerouted traffic for " << dstIp << " to " << nextHop << " (" << action << ")");
    WriteEvent("reroute", "Traffic for " + dstIp + " rerouted to " + nextHop);
}

// Custom application for dummy packet verification
class DummyPacketApp : public Application {
public:
    DummyPacketApp();
    virtual ~DummyPacketApp();
    void Setup(Ptr<Socket> socket, Address address, uint32_t packetSize, uint32_t nPackets, DataRate dataRate);
private:
    virtual void StartApplication(void);
    virtual void StopApplication(void);
    void ScheduleTx(void);
    void SendPacket(void);
    void HandleRead(Ptr<Socket> socket);
    Ptr<Socket>     m_socket;
    Address         m_peer;
    uint32_t        m_packetSize;
    uint32_t        m_nPackets;
    DataRate        m_dataRate;
    EventId         m_sendEvent;
    bool            m_running;
    uint32_t        m_packetsSent;
    Callback<void, bool> m_verificationCallback; // Callback for verification result
public:
    void SetVerificationCallback(Callback<void, bool> cb) {
        m_verificationCallback = cb;
    }
};

DummyPacketApp::DummyPacketApp()
    : m_socket(0),
      m_packetSize(0),
      m_nPackets(0),
      m_dataRate(0),
      m_running(false),
      m_packetsSent(0) {
}

DummyPacketApp::~DummyPacketApp() {
    m_socket = 0;
}

void DummyPacketApp::Setup(Ptr<Socket> socket, Address address, uint32_t packetSize, uint32_t nPackets, DataRate dataRate) {
    m_socket = socket;
    m_peer = address;
    m_packetSize = packetSize;
    m_nPackets = nPackets;
    m_dataRate = dataRate;
}

void DummyPacketApp::StartApplication(void) {
    m_running = true;
    m_packetsSent = 0;
    if (Inet6SocketAddress::IsMatchingType(m_peer)) {
        m_socket->Bind6();
    } else {
        m_socket->Bind();
    }
    m_socket->Connect(m_peer);
    m_socket->SetRecvCallback(MakeCallback(&DummyPacketApp::HandleRead, this));
    SendPacket();
}

void DummyPacketApp::StopApplication(void) {
    m_running = false;
    if (m_sendEvent.IsPending()) { // Fixed: Use IsPending() instead of deprecated IsRunning()
        Simulator::Cancel(m_sendEvent);
    }
    if (m_socket) {
        m_socket->Close();
    }
}

void DummyPacketApp::SendPacket(void) {
    Ptr<Packet> packet = Create<Packet>(m_packetSize);
    int actual = m_socket->Send(packet);
    if (actual > 0) {
        m_packetsSent++;
        NS_LOG_INFO("Dummy packet sent: " << packet->GetSize() << " bytes");
    }
    if (m_packetsSent < m_nPackets) {
        ScheduleTx();
    }
}

void DummyPacketApp::ScheduleTx(void) {
    if (m_running) {
        Time tNext(Seconds(m_packetSize * 8 / static_cast<double>(m_dataRate.GetBitRate())));
        m_sendEvent = Simulator::Schedule(tNext, &DummyPacketApp::SendPacket, this);
    }
}

void DummyPacketApp::HandleRead(Ptr<Socket> socket) {
    Ptr<Packet> packet;
    Address from;
    while ((packet = socket->RecvFrom(from))) {
        if (packet->GetSize() > 0) {
            NS_LOG_INFO("Dummy packet ACK received from " << InetSocketAddress::ConvertFrom(from).GetIpv4());
            // Verification successful
            if (!m_verificationCallback.IsNull()) {
                m_verificationCallback(true);
            }
            StopApplication();
            break;
        }
    }
}

// Function to send dummy packet for verification
void SendDummyPacketForVerification(Ptr<Node> sourceNode, Ipv4Address destIp, uint16_t destPort, Callback<void, bool> verificationCallback) {
    // Create a socket
    TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
    Ptr<Socket> sinkSocket = Socket::CreateSocket(sourceNode, tid);
    Address sinkAddress(InetSocketAddress(destIp, destPort));
    // Create the dummy packet application
    Ptr<DummyPacketApp> app = CreateObject<DummyPacketApp>();
    app->Setup(sinkSocket, sinkAddress, 64, 1, DataRate("64Kbps"));
    app->SetVerificationCallback(verificationCallback);
    sourceNode->AddApplication(app);
    app->SetStartTime(Seconds(Simulator::Now().GetSeconds()));
    app->SetStopTime(Seconds(Simulator::Now().GetSeconds() + 2.0)); // Timeout after 2 seconds
    NS_LOG_INFO("Dummy packet verification initiated for " << destIp << ":" << destPort);
}

// Function to periodically check for rerouting commands
void CheckAndReroute(NodeContainer& nodes) {
    std::map<std::string, std::string> command;
    if (ReadCommand(command)) {
        std::string action = command["action"];
        std::string dstIp = command["dst_ip"];
        if (!dstIp.empty() && !action.empty()) {
            DynamicReroute(nodes.Get(0), dstIp, action); // Node 0 is the router
        }
    }
    // Reschedule this function every 1 second
    Simulator::Schedule(Seconds(1.0), &CheckAndReroute, nodes);
}

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
    LogComponentEnable("BotIoTTrafficSimulation_NoDDoS_Eth_PCAP_Enhanced", LOG_LEVEL_INFO);
    // Nodes: 0=Router/Attacker, 1=Victim, 2=Normal Client, 3=Normal Server, 4=Sinkhole, 5=Honeypot
    NodeContainer nodes;
    nodes.Create(6); // Added Sinkhole and Honeypot
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
    // Links to Sinkhole and Honeypot
    PointToPointHelper p2pSink;
    p2pSink.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
    p2pSink.SetChannelAttribute("Delay",   StringValue("1ms"));
    NetDeviceContainer dev04 = p2pSink.Install(NodeContainer(nodes.Get(0), nodes.Get(4))); // Router to Sinkhole
    NetDeviceContainer dev05 = p2pSink.Install(NodeContainer(nodes.Get(0), nodes.Get(5))); // Router to Honeypot
    // Internet + IPs
    InternetStackHelper stack;
    stack.Install(nodes);
    Ipv4AddressHelper address;
    address.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer if01 = address.Assign(dev01);
    address.SetBase("10.1.2.0", "255.255.255.0");
    Ipv4InterfaceContainer if23 = address.Assign(dev23);
    address.SetBase("10.1.3.0", "255.255.255.0");
    Ipv4InterfaceContainer if04 = address.Assign(dev04); // Sinkhole gets 10.1.3.2
    address.SetBase("10.1.4.0", "255.255.255.0");
    Ipv4InterfaceContainer if05 = address.Assign(dev05); // Honeypot gets 10.1.4.2
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

            // Capture necessary variables by value for the lambda
            uint16_t capturedTheftPort = theftPort;
            std::string capturedTheftPerFlowRate = theftPerFlowRate;
            uint32_t capturedTheftPacketSize = theftPacketSize;
            double capturedTheftStartTime = theftStartTime;
            double capturedTheftDuration = theftDuration;
            NodeContainer capturedNodes = nodes; // Capture the entire container
            Ipv4InterfaceContainer capturedIf01 = if01; // Capture interface info

            // Schedule dummy packet verification before starting the real flow
            Simulator::Schedule(Seconds(start - 0.5), [=]() {
                // Define the verification callback as a lambda that captures by value
                auto verificationCallback = [=](bool success) {
                    if (success) {
                        NS_LOG_INFO("Route verification successful. Starting theft flow.");
                        WriteEvent("verification", "Route verification successful for Theft flow.");
                    } else {
                        NS_LOG_WARN("Route verification failed. Theft flow may be compromised.");
                        WriteEvent("verification", "Route verification FAILED for Theft flow.");
                    }
                    // Start the real flow regardless, for simulation purposes
                    OnOffHelper exfil("ns3::TcpSocketFactory",
                                      InetSocketAddress(Ipv4Address("10.1.1.2"), capturedTheftPort));
                    exfil.SetAttribute("OnTime",     StringValue("ns3::ConstantRandomVariable[Constant=1]"));
                    exfil.SetAttribute("OffTime",    StringValue("ns3::ConstantRandomVariable[Constant=0]"));
                    exfil.SetAttribute("DataRate",   StringValue(capturedTheftPerFlowRate));   // ~11 pps
                    exfil.SetAttribute("PacketSize", UintegerValue(capturedTheftPacketSize));  // 1450B
                    auto app = exfil.Install(capturedNodes.Get(0));
                    double realStart = Simulator::Now().GetSeconds();
                    app.Start(Seconds(realStart));
                    app.Stop(Seconds(realStart + capturedTheftDuration - (realStart - capturedTheftStartTime)));
                };

                // Call the function with the callback
                SendDummyPacketForVerification(capturedNodes.Get(0), capturedIf01.GetAddress(1), capturedTheftPort, verificationCallback);
            });
        }
    }
    // Start the periodic rerouting command checker
    Simulator::Schedule(Seconds(1.0), &CheckAndReroute, nodes);
    // Single Ethernet PCAP on the victim side of Node0<->Node1
    NS_LOG_INFO("Enabling victim-side Ethernet PCAP...");
    csma.EnablePcap(pcapPrefix, dev01.Get(1), true); // -> botiot-aligned-traffic-1-0.pcap
    Simulator::Stop(Seconds(180.0));
    Simulator::Run();
    Simulator::Destroy();
    return 0;
}