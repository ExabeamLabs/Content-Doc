#### Parser Content
```Java
{
Name = cef-ping-app-login-1
  DataType = "app-login"
  Conditions = [ """CEF:""", """|Ping Identity|PingFederate|""", """|SSO|""", """msg=success""" ]
}

${PingParserTemplates.cef-ping-events-1}{
  Name = cef-ping-failed-app-login-1
  DataType = "failed-app-login"
  Conditions = [ """CEF:""", """|Ping Identity|PingFederate|""", """|SSO|""", """msg=failure""" ]
}

${PingParserTemplates.ping-events}{
  Name = ping-auth-successful-1
  DataType = "authentication-successful"
  Conditions = [ """|AUTHN_ATTEMPT|""", """success|""" ]
}

${PingParserTemplates.ping-events}{
  Name = ping-auth-failed-1
  DataType = "authentication-failed"
  Conditions = [ """|AUTHN_ATTEMPT|""", """failure|""" ]
  Fields = ${PingParserTemplates.ping-events.Fields} [
    """(\|\s*(AUTHN_ATTEMPT|OAuth|SSO)\s*\|)\s*([^\|]*\|){9}\s*(|({failure_reason}[^\|]*?))\s*\|""",
  ]
}

${PingParserTemplates.ping-events}{
  Name = ping-auth-successful-2
  DataType = "authentication-successful"
  Conditions = [ """|OAuth|""", """success|""" ]
}

${PingParserTemplates.ping-events}{
  Name = ping-auth-failed-2
  DataType = "authentication-failed"
  Conditions = [ """|OAuth|""", """failure|""" ]
  Fields = ${PingParserTemplates.ping-events.Fields} [
    """(\|\s*(AUTHN_ATTEMPT|OAuth|SSO)\s*\|)\s*([^\|]*\|){9}\s*(|({failure_reason}[^\|]*?))\s*\|""",
  ]
}

${PingParserTemplates.ping-events}{
  Name = ping-app-login
  DataType = "app-login"
  Conditions = [ """|SSO|""", """success|""" ]
}

{
  Name=raw-protectwise-alert
  Vendor = ProtectWise
  Product = NDR
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """ protectwise-emitter[""" ]
  Fields = [
    """({time}\d{1,4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.[^\s.]+)""",
    """\d\d:\d\d:\d\d\s({host}[^=]+?).\s<""",
    """src\s-\s({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """dst\s-\s({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """classification:\s({alert_type}[^,]*)""",
    """description:\s({alert_name}[^,]*)""",
  ]
 }
```