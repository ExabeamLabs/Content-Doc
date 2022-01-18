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
    """\Wrt=({time}\d{1,100})""",
    """({host}\S+)\s{1,100}CEF:\d{1,100}\|"""
    """\|43-2630({event_code}4662)0\|""",
    """\Wact=({outcome}.+?)\s{1,100}(\w+=|$)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wsntdom=({domain}.+?)\s{1,100}(\w+=|$)""",
    """\Wshost=({src_host}.+?)\s{1,100}(\w+=|$)""",
    """\Wsuser=({user}.+?)\s{1,100}(\w+=|$)""",
    """\WnitroSecurity_ID=({user_sid}.+?)\s{1,100}(\w+=|$)""",
    """\WnitroSource_Logon_ID=({logon_id}.+?)\s{1,100}(\w+=|$)""",
    """\WnitroLogon_Type=({logon_type}.+?)\s{1,100}(\w+=|$)"""
  ]


}
```