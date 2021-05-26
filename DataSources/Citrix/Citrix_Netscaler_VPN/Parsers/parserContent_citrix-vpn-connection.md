#### Parser Content
```Java
{
Name = citrix-vpn-connection
    Vendor = Citrix
    Product = Citrix Netscaler VPN
    Lms = Direct
    DataType = "vpn-connection"
    TimeFormat = "MM/dd/yyyy:HH:mm:ss"
    Conditions = [""" SSLVPN """, """Access Allowed""", """ Duration """, """ Total_bytes_send """ ]
    Fields = [
     """exabeam_host=({host}[\w\-.]{1,2000})""",
     """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
     """\w+\s{1,100}\d{1,100}\s{1,100}\d\d:\d\d:\d\d\s{1,100}({host}[\w\-.]{1,2000})""",
      """({host}[^\s]{1,2000})\s{0,100}:\s{0,100}SSLVPN \w+\s""",
      """\sEnd_time(\s{0,100}\&quot;)?\s{0,100}"?({time}\d{1,100}\/\d{1,100}\/\d{1,100}:\d{1,100}:\d{1,100}:\d{1,100})""",
      """\sUser\s{0,100}({user}[^\-\s]{1,2000})\s{0,100}\-""",
      """({event_name}SSLVPN \w+)""",
      """\sSessionId:\s{0,100}({session_id}\d{1,100})""",
      """\sSource\s{0,100}({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}):({src_port}\d{1,100})""",
      """\sNat_ip\s{0,100}({src_translated_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
      """\sVserver\s{0,100}({dest_translated_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}):({dest_translated_port}\d{1,100})""",
      """\sDestination\s{0,100}({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}):({dest_port}\d{1,100})""",
      """\sDuration\s{0,100}({duration}\d{2}:\d{2}:\d{2})""",
      """\sTotal_bytes_send\s{0,100}({bytes_out}\d{1,100})""",
      """\sTotal_bytes_recv\s{0,100}({bytes_in}\d{1,100})""",
      """\sAccess\s{0,100}({action}[^\s]{1,2000})\s""",
      """\sGroup\(s\)\s{0,100}("|&quot;)({access_group}[^"]{1,2000}?)(&quot;|")"""
    ]
}
```