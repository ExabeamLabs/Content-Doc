#### Parser Content
```Java
{
Name = bluecat-networks-dhcp
    Vendor = BlueCat Networks
    Product = BlueCat Networks DHCP
    Lms = ArcSight
    DataType = "dhcp"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """ dhcpd[""", """ DHCPIDENT:""", """| IP=""", """| Hostname=""" ]
    Fields = [
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """exabeam_host=({host}[\w.\-]{1,2000})""",
      """Hostname=(((?i)\[?None\]?)|({src_host}[^|]{1,2000}?))\s{0,100}\|""",
      """MAC=({src_mac}[^\s]{1,2000}?)\s{1,100}""",
      """IP=({src_ip}[A-Fa-f0-9.:]{1,2000}?)\s{0,100}\|""",
      """IP=[^|]{1,2000}\|\s{0,100}({additional_info}[^"]{1,2000}?)\s{0,100}("|$)""",
    ]
 

}
```