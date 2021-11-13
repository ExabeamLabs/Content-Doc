#### Parser Content
```Java
{
Name = nokia-vitalqip-computer-logon-1
  DataType = "dhcp"
  Conditions = [ """ Lucent_DHCP_Service""", """]: DHCP_RenewLease: """ ]

nokia-vitalqip-logon-events = {
    Vendor = Nokia VitalQIP
    Product = Nokia VitalQIP
    Lms = Splunk
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Fields = [
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """exabeam_host=({host}[^\s]{1,2000})""",
      """Host=({dest_host}[\w\-.]{1,2000})""",
      """IP=({dest_ip}[A-Fa-f\d:.]{1,2000})""",
      """MAC=({dest_mac}\S{1,2000})""",
      """Domain=({domain}[^\s]{1,2000})""",
    
}
```