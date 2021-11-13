#### Parser Content
```Java
{
Name = sourcefire-estreamer-alert
  Vendor = Cisco
  Product = Cisco Firepower
  Lms = Splunk
# "Thu Oct 30 09:02:17 2014 archive_timestamp=1414674137 sensor_id=2 event_id=78543 event_sec=1414674137 event_usec=479752 sid=7 gen=119 rev=1 class=24 priority=3 src_addr=10.0.0.1 dst_addr=23.19.138.19 src_port=53386 dst_port=80 ip_proto=6 impact_flag=2"
#  Lookup = [
#	field=alert_type
#	1,Not Suspicious Traffic
#	2,Unknown Traffic
#	3,Potentially Bad Traffic
#	4,Attempted Information Leak
#	5,Information Leak
#	6,Large Scale Information Leak
#	7,Attempted Denial of Service
#	8,Denial of Service
#	9,Attempted User Privilege Gain
#	10,Unsuccessful User Privilege Gain
#	11,Successful User Privilege Gain
#	12,Attempted Administrator Privilege Gain
#	13,Successful Administrator Privilege Gain
#	14,Decode of an RPC Query
#	15,Executable Code was Detected
#	16,A Suspicious String was Detected
#	17,A Suspicious Filename was Detected
#	18,An Attempted Login Using a Suspicious Username was Detected
#	19,A System Call was Detected
#	20,A TCP Connection was Detected
#	21,A Network Trojan was Detected
#	22,A Client was Using an Unusual Port
#	23,Detection of a Network Scan
#	24,Detection of a Denial of Service Attack
#	25,Detection of a Non-Standard Protocol or Event
#	26,Generic Protocol Command Decode
#	27,Access to a Potentially Vulnerable Web Application
#	28,Web Application Attack
#	29,Misc Activity
#	30,Misc Attack
#	31,Generic ICMP Event
#	32,Inappropriate Content was Detected
#	33,Potential Corporate Privacy Violation
#	34,Attempt to Login By a Default Username and Password
#]
### NOTE: we only look at the following alert codes 6,21,17,12,13
  DataType = "alert"
  TimeFormat = "epoch_sec"
  Conditions = [ """archive_timestamp=""","""event_usec=""" ]
  Fields = [
	     """event_sec=({time}\d{1,100})""",
             """\sevent_id=({alert_id}\d{1,100})\s{1,100}.+?class=({alert_name}(6|12|13|17|21))\s{1,100}priority=({alert_severity}\d{1,100})\s{1,100}src_addr=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s{1,100}dst_addr=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
	     """exabeam_host=({host}[\w.\-]{1,2000})"""
  ]
  DupFields=["alert_name->alert_type"]
  SOAR {
    IncidentType = "generic"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->description", "alert_severity->sourceSeverity"]
    NameTemplate = """Cisco Sourcefire Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name ="src_address", Fields=["src_ip->ip_address"]

}
```