#### Parser Content
```Java
{
Name = n-forwarded-cef-4662
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = NitroCefSyslog
  DataType = "object-access"
  TimeFormat = "epoch"
  Conditions = [ """|McAfee|ESM|""", """|43-263046620|""", """|An operation was performed on an object|""" ]
  Fields = [
    """({event_name}An operation was performed on an object)""",
    """\Wrt=({time}\d+)""",
    """({host}\S+)\s+CEF:\d+\|"""
    """\|43-2630({event_code}4662)0\|""",
    """\Wact=({outcome}.+?)\s+(\w+=|$)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
    """\Wsntdom=({domain}.+?)\s+(\w+=|$)""",
    """\Wshost=({src_host}.+?)\s+(\w+=|$)""",
    """\Wsuser=({user}.+?)\s+(\w+=|$)""",
    """\WnitroSecurity_ID=({user_sid}.+?)\s+(\w+=|$)""",
    """\WnitroSource_Logon_ID=({logon_id}.+?)\s+(\w+=|$)""",
    """\WnitroLogon_Type=({logon_type}.+?)\s+(\w+=|$)"""
  ]
}
```