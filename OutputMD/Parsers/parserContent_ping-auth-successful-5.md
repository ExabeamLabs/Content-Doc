#### Parser Content
```Java
{
Name = ping-auth-successful-5
  DataType = "authentication-successful"
  Conditions = [ """| OAuth|""", """success|""" ]
}
${PingParserTemplates.ping-events}{
  Name = ping-auth-failed-5
  DataType = "authentication-failed"
  Conditions = [ """| OAuth|""", """failure|""" ]
  Fields = ${PingParserTemplates.ping-events.Fields} [
    """(\|\s*(AUTHN_ATTEMPT|OAuth|SSO)\s*\|)\s*([^\|]*\|){9}\s*(|({failure_reason}[^\|]*?))\s*\|""",
  ]
}
${PingParserTemplates.ping-events}{
  Name = ping-app-login-4
  DataType = "app-login"
  Conditions = [ """| SSO|""", """success|""" ]
}
${PingParserTemplates.ping-events}{
  Name = ping-failed-app-login-4
  DataType = "failed-app-login"
  Conditions = [ """| SSO|""", """failure|""" ]
}

{
  Name = lumension-failed-usb-activity-3
  Vendor = Lumension
  Product = Lumension
  Lms = Direct
  DataType = "usb-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ ""","WRITE-DENIED",""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)","[^"]*","(({domain}[^"\\\/]+)[\\\/]+)?({user}[^"\\\/]+)?","({user_ou}[^"]+)","({activity}WRITE-DENIED)","({host}[^"]+)",("[^"]*",){2}"({file_path}[^"]+)",""",
    ""","({process_name}[^"]+)"\s*$""",
  ]
}
```