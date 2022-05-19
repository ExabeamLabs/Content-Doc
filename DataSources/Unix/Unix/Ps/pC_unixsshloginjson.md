#### Parser Content
```Java
{
Name = unix-ssh-login-json
  Product = Unix
  DataType = "ssh-login"
  Conditions = [ """"ident":"sshd""", """Accepted publickey for""" ]
  Fields = ${UnixParserTemplates.unix-activity-json.Fields}[
    """Accepted ({auth}\S+) for (({domain}[^\\:]{1,2000})\\+)?({user}[\w.'\-\\$]{1,2000})""",
    """from ({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\s{1,100}from\s{1,100}(::[\w]{1,2000}:)?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
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