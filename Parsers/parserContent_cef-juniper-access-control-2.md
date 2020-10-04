#### Parser Content
```Java
{
Name = cef-juniper-access-control-2
  DataType = "access-control"
  Conditions = [ """CEF:""", """|McAfee|ESM|""", """|SecureAccess_v7 Added user to authentication server|""" ]
}

${JuniperParserTemplates.cef-juniper-vpn-events}{
  Name = cef-juniper-access-control-3
  DataType = "access-control"
  Conditions = [ """CEF:""", """|McAfee|ESM|""", """|SecureAccess_v7 Removed User from Authentication Server|""" ]
}

{
  Name = juniper-vpn-close
  Vendor = Juniper Networks
  Product = Juniper VPN
  Lms = Splunk
  DataType = "vpn-end"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ Closed connection to """, """ bytes read """, """ bytes written """ ]
  Fields = [
    """(Juniper|PulseSecure):\s*({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """"@timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)""",
    """\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+({host}[\w\.-]+)\s+\S*?[\[:\s]""",
    """exabeam_host=([^=]+?@\s*)?({host}[^\s]+)""",
    """({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[\w\-\.]+)\s*(Juniper|PulseSecure):""",
    """:\s*({time}\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s""",
    """- \[({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]\s+(?:({domain}\w+)\\)?({user}[^\(\[]+?)[\(\[]""",
    """Closed connection to (?:({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w.\-]+))""",
    """- Closed connection to \S+\s+port ({dest_port}\d+)""",
    """\stime="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\suser=({user}.+?)(\s+\w+=|\s*$)""",
    """\ssrc=({src_ip}[a-fA-F\d.:]+)""",
    """\safter\s+({session_duration}\d+)\s+seconds""",
    """\swith\s+({bytes_in}\d+)\s+bytes read""",
    """\sand\s+({bytes_out}\d+)\s+bytes written"""
    """\sfw=({firewall}[a-fA-F\d.:]+)""",
    """\svpn=[\\"]*({vpn}.+?)[\\"]*(\s+\w+=|\s*$)""",
    """\srealm=[\\"]*({realm}.+?)[\\"]*(\s+\w+=|\s*$)""",
    """\sroles=[\\"]*({roles}.+?)[\\"]*(\s+\w+=|\s*$)""",
    """\sproto=({protocol}[^=]+?)(\s+\w+=|\s*$)""",
    """\ssrcport=({src_port}\d+)""",
    """\sdstip=({dest_ip}[a-fA-F\d.:]+)""",
    """\sdstname=({dest_host}[^=]+?)(\s+\w+=|\s*$)""",
    """\sport=({dest_port}\d+)""",
    """\stype=({vpn_type}[^=]+?)(\s+\w+=|\s*$)""",
    """\sop=({op}[^=]+?)(\s+\w+=|\s*$)""",
    """\sarg="({arg}[^"]+)""",
    """\sresult=({result}[^=]+?)(\s+\w+=|\s*$)""",
    """\ssent=({bytes_out}\d+)""",
    """\srcvd=({bytes_in}\d+)""",
    """\sagent="({agent}[^"]+)""",
    """\sduration=({session_duration}\d+)""",
    """\smsg="({additional_info}[^"]+)""",
  ]
}
```