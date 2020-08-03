#### Parser Content
```Java
{
Name = cef-f5-vpn-start
  Vendor = F5
  Product = Access Policy Manager
  Lms = ArcSight
  DataType = "vpn-start"
  TimeFormat = "epoch"
  Conditions = [ """|F5|APM|""", """|New session from client|""", """01490500:5:""" ]
  Fields = [
    """\srt=({time}\d+)""",
    """\smsg=[^=]*? from client IP ({src_ip}[a-fA-F\d.:]+) [^=]*? at VIP ({src_translated_ip}[a-fA-F\d.:]+)""",
    """\ssrc=({src_ip}[a-fA-F\d.:]+)""",
    """\scs4=({session_id}.+?)(?:\s+[\w.]+=|\s*$)""",
    """\sdvc=({host}[a-fA-F\d.:]+)""",
    """\sdvchost=({host}.+?)(?:\s+[\w.]+=|\s*$)""",
    """\sad\.VIPAddress=({src_translated_ip}[a-fA-F\d.:]+)"""
  ]
}

{
  Name = f5-vpn-session-start
  Vendor = F5
  Product = Big-IP
  Lms = Splunk
  DataType = "vpn-start"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """01490500:5:""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\d\d:\d\d\s+({host}[^\s]+)\s([^\s]+\s)?[^\s]+\[\d+\]""",
    """"host":\{"name":"({host}[^"]+)""",
    """hostname="({host}[^"]+)""",
    """\s+01490500:5:.*?({session_id}[^\s:]+): New session""",
    """client IP ({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
  ]
}
```