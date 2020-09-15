#### Parser Content
```Java
{
Name = q-aruba-failed-nac-logon
  DataType = "nac-failed-logon"
  Conditions = [ """ Logs_Failed Authentication """, """Common.NAS-IP-Address=""", """Common.Request-Timestamp=""" ]
}

${HPEParserTemplates.q-aruba-nac-logon}{
  Name = q-aruba-failed-nac-logon-1
  DataType = "nac-failed-logon"
  TimeFormat = "yyyy-MM-dd HH:mm:ss-SS"
  Conditions = [ """ Failed Auth """, """Common.NAS-IP-Address=""" ]
  Fields = ${HPEParserTemplates.q-aruba-nac-logon.Fields} [
    """Common\.Request-Timestamp=({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d-\d+)"""
]
}

${HPEParserTemplates.q-aruba-nac-logon}{
  Name = q-aruba-nac-logon-1
  DataType = "nac-logon"
  Conditions = [ """ Logs_Guest Access """, """Common.Request-Timestamp=""" ]
}

${HPEParserTemplates.q-aruba-nac-logon}{
  Name = q-aruba-nac-logon-2
  DataType = "nac-logon"
  Conditions = [ """ Logs_Logged In User """, """Common.Request-Timestamp=""" ]
}

${HPEParserTemplates.q-aruba-nac-logon}{
  Name = q-aruba-nac-logon-4
  DataType = "nac-logon"
  Conditions = [ """,RADIUS.""", """Common.Request-Timestamp=""", """ Session """ ]
}

{
  Name = q-aruba-nac-logon-3
  Vendor = HPE
  Product = Aruba ClearPass Access Control and Policy Management
  Lms = QRadar
  DataType = "nac-logon"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSSZ"
  Conditions = [ """ Radius Accounting """, """RADIUS.Acct-Timestamp=""" ]
  Fields = [
    """RADIUS\.Acct-Timestamp=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d(\.\d+)?[\+\-]\d+)""",
    """\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d,\d+ ({host}[\w\-.]+)""",
    """RADIUS\.Acct-Username=(?:({user_type}host)/)?(({domain}[^\\\s,]+)\\+)?(anonymous|({user}[^\\\s,@]+))""",
    """RADIUS\.Acct-Username=({user_email}[^\\\s,@]+@[^\\\s,@]+)""",
    """RADIUS\.Acct-Service-Name=({network}[^,]+)""",
    """RADIUS\.Acct-NAS-IP-Address=({dest_ip}[A-Fa-f:\d.]+)""",
    """RADIUS\.Acct-Framed-IP-Address=({src_ip}[A-Fa-f:\d.]+)""",
  ]
  DupFields = [ "host->auth_server" ]
}
```