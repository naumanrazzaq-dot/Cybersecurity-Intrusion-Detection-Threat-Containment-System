#include <iostream>
#include <string>
#include <iomanip>

using namespace std;

// Base Abstract Class
class NetworkSensor {
protected:
    string sensorID;
    long packetsInspected;

public:
    static int activeSensors;
    static int detectedThreatIncidents;

    NetworkSensor(string id, long packets)
        : sensorID(id), packetsInspected(packets) {
        activeSensors++;
    }

    virtual ~NetworkSensor() {
        cout << "[DISCONNECTED] Sensor " << sensorID << " tap removed from interface." << endl;
        activeSensors--;
    }

    // Pure Virtual Interfaces
    virtual double calculateThreatScore() const = 0;
    virtual void dispatchAuditReport() const = 0;
};

// Static initializations outside class boundary
int NetworkSensor::activeSensors = 0;
int NetworkSensor::detectedThreatIncidents = 0;

// Derived Class 1: Deep Packet Inspection (DPI) Module
class DeepPacketInspectionSensor : public NetworkSensor {
private:
    int payloadSignaturesMatched;
    double encryptedTrafficRatio;

public:
    DeepPacketInspectionSensor(string id, long packets, int signatures, double encRatio)
        : NetworkSensor(id, packets),
          payloadSignaturesMatched(signatures),
          encryptedTrafficRatio(encRatio) {}

    ~DeepPacketInspectionSensor() override {
        cout << " -> Flushing signature pattern tables for " << sensorID << "..." << endl;
    }

    double calculateThreatScore() const override {
        // High signatures matched and high unverified encrypted ratios elevate threat
        double score = (payloadSignaturesMatched * 15.0) + (encryptedTrafficRatio * 20.0);
        return (score > 100.0) ? 100.0 : score;
    }

    void dispatchAuditReport() const override {
        double score = calculateThreatScore();
        if (score >= 50.0) NetworkSensor::detectedThreatIncidents++;

        cout << "\n==============================================" << endl;
        cout << "   DPI FIREWALL SENSOR: " << sensorID << endl;
        cout << "==============================================" << endl;
        cout << "  Packets Scanned      : " << packetsInspected << endl;
        cout << "  Signatures Matched   : " << payloadSignaturesMatched << endl;
        cout << "  Encrypted Ratio      : " << fixed << setprecision(1) << (encryptedTrafficRatio * 100.0) << " %" << endl;
        cout << "  Threat Severity      : " << fixed << setprecision(2) << score << " / 100" << endl;
        cout << "  Containment Action   : " << (score >= 50.0 ? "PACKET DROP & ISOLATION" : "FORWARD ALLOWED") << endl;
        cout << "==============================================" << endl;
    }
};

// Derived Class 2: Distributed Denial of Service (DDoS) Rate Limiter
class DDoSSanitizerSensor : public NetworkSensor {
private:
    int synRequestsPerSecond;
    int blockedIPAddresses;

public:
    DDoSSanitizerSensor(string id, long packets, int synRate, int blockedIPs)
        : NetworkSensor(id, packets),
          synRequestsPerSecond(synRate),
          blockedIPAddresses(blockedIPs) {}

    ~DDoSSanitizerSensor() override {
        cout << " -> Releasing IP ban lists and TCP bucket filters for " << sensorID << "..." << endl;
    }

    double calculateThreatScore() const override {
        double score = (synRequestsPerSecond / 100.0) + (blockedIPAddresses * 2.0);
        return (score > 100.0) ? 100.0 : score;
    }

    void dispatchAuditReport() const override {
        double score = calculateThreatScore();
        if (score >= 40.0) NetworkSensor::detectedThreatIncidents++;

        cout << "\n==============================================" << endl;
        cout << "   DDOS MITIGATION SENSOR: " << sensorID << endl;
        cout << "==============================================" << endl;
        cout << "  Packets Scanned      : " << packetsInspected << endl;
        cout << "  SYN Rate             : " << synRequestsPerSecond << " req/sec" << endl;
        cout << "  Blacklisted IPs      : " << blockedIPAddresses << endl;
        cout << "  Threat Severity      : " << fixed << setprecision(2) << score << " / 100" << endl;
        cout << "  Mitigation Status    : " << (score >= 40.0 ? "RATE-LIMIT SCRUBBING ENGAGED" : "NORMAL TRAFFIC") << endl;
        cout << "==============================================" << endl;
    }
};

int main() {
    cout <<Ready when you are—what would you like another one of? A coding challenge, idea, movie recommendation, or something else?
