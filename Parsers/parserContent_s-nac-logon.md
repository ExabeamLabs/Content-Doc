#### Parser Content
```Java
{
Name = s-nac-logon
  Conditions = [ "Passed-Authentication: Authentication succeeded" ]
}???

${CiscoParsersTemplates.s-nac-logon}{
 Name = s-nac-logon-1
 Conditions = [ """Device-Administration: """, """ succeeded""" , """Protocol="""]
}???

${CiscoParsersTemplates.s-nac-logon}{
  Name = s-nac-failed-logon-1
  Conditions = [ """Device-Administration: """, """ failed""" ]
}???

${CiscoParsersTemplates.s-nac-logon}{
  Name = s-nac-failed-logon-2
  Conditions = [ """CISE_Failed_Attempts""", """ failed""" ]
}???

{
  Name = s-nac-logon-2
  Vendor = Cisco
  Product = Cisco ISE
  Lms = Direct
  DataType = "nac-logon"
  TimeFormat = "epoch"
  Conditions = [ """CISE_Passed_Authentications""", """|Cisco|Cisco ISE|""", """CEF:""" ]
  Fields = [
    """\Wrt=({time}\d+)""",
    """exabeam_host=({host}[^\s]+)""",
    """ahost=({host}[^\s]+)"""
    """shost=({src_host}[^\s]+)""",
    """({event_name}CISE_Passed_Authentications)""",
    """suser=({user}[^\s]+)""",
    """dhost=({dest_host}[^\s]+)""",
    """dst=({dest_ip}[A-Fa-f:\d.]+)""",
    """dst=({auth_server}[A-Fa-f:\d.]+)""",
    """dpt=({dest_port}\d+)""",
    """Cisco ISE\|(|[^\|]+)\|({event_code}\d+)\|""",
    """deviceSeverity=({severity}[^\s]+)""",
    """cs1=({auth_method}[^\s]+)""",
    """ad.User=({user}[^\s]+)""",
    """NetworkDeviceName\\*=({network}[^,\s]+)"""
  ]
  DupFields = ["dest_host->auth_server"]
}
```