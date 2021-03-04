#### Parser Content
```Java
{
Name = citrix-vpn-connection
    Vendor = Netscaler VPN
    Lms = Direct
    DataType = "vpn-connection"
    TimeFormat = "MM/dd/yyyy:HH:mm:ss"
    Conditions = [""" SSLVPN """, """Access Allowed""", """ Duration """, """ Total_bytes_send """ ]
    Fields = [
     """exabeam_host=([^=]+@\s*)?({host}\S+)""",
     """\w+\s+\d+\s+\d\d:\d\d:\d\d\s+({host}[\w\-.]+)""",
      """({host}[^\s]+)\s*:\s*SSLVPN \w+\s""",
      """\sEnd_time\s*"({time}\d+\/\d+\/\d+:\d+:\d+:\d+)""",
      """\sUser\s*({user}[^\-\s]+)\s*\-""",
      """({event_name}SSLVPN \w+)""",
      """\sSessionId:\s*({session_id}\d+)""",
      """\sSource\s*({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}):({src_port}\d+)""",
      """\sNat_ip\s*({src_translated_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
      """\sVserver\s*({dest_translated_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}):({dest_translated_port}\d+)""",
      """\sDestination\s*({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}):({dest_port}\d+)""",
      """\sDuration\s*({duration}\d{2}:\d{2}:\d{2})""",
      """\sTotal_bytes_send\s*({bytes_out}\d+)""",
      """\sTotal_bytes_recv\s*({bytes_in}\d+)""",
      """\sAccess\s*({action}[^\s]+)\s""",
      """\sGroup\(s\)\s*"({access_group}[^"]+)""""
    ]
}
```