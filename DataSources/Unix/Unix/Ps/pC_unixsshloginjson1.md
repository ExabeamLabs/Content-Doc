#### Parser Content
```Java
{
Name = unix-ssh-login-json-1
  Product = Unix
  DataType = "ssh-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """destinationServiceName =Azure""", """"operationName":"LinuxSyslogEvent"""", """ ssh2""", """Accepted """ ]
  Fields = ${UnixParserTemplates.unix-activity-json.Fields}[
    """Accepted\s({auth}\S{1,2000})\sfor\s(({domain}[^\\"]{1,2000})\\{1,25})?({user}[^\s"]{1,2000})\s""",
    """\s{1,100}from\s{1,100}(::ffff:)?({src_ip}[A-Fa-f\d:.]{1,2000})\sport\s({src_port}\d{1,100})\s"""
  ]

unix-activity-json = {
    Vendor = Unix
    Lms = Direct
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Fields = [
      """"host(name)?":"({host}[^"]{1,2000})""",
      """"ident":"({event_code}[^"]{1,2000})""",
      """"pid":"({pid}\d{1,100})""",
      """"time(stamp)?":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ?)""",
    
}
```