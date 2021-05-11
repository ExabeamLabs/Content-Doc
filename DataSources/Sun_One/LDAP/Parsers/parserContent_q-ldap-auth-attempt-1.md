#### Parser Content
```Java
{
Name = q-ldap-auth-attempt-1
  Vendor = Sun One
  Product = LDAP
  Lms = QRadar
  DataType = "authentication-attempt"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"authentication":""", """"status":"""", """"network":"""", """"type":"ldap"""", """LDAP bind without requesting signing""" ]
  Fields = [
    """"@timestamp":"({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100}Z)""",
    """"index":"[^\{\}]*?"host":"({host}[\w\-.]+)""",
    """"host":"({host}[\w\-.]+)"[^\{\}]*?"index":"""",
    """"status":"({outcome}[^"]+)""",
    """"destination":\{.*?"ipv4":"({dest_ip}[A-Fa-f:\d.]+)""",
    """"destination":\{.*?"host":"({dest_host}[\w\-.]+)""",
    """"source":\{.*?"ipv4":"({src_ip}[A-Fa-f:\d.]+)""",
    """"source":\{.*?"host":"({src_host}[\w\-.]+)""",
    """"user":\{?[^\{\}]*?"realm":"({realm}[^"\s]+)"""",
    """"user":\{?[^\{\}]*?"uid":"({user}[^"\s]+)"""",
    """"message":"({additional_info}[^"]+)""",
    """"domain":"({domain}[^"\s]+)""",
  ]
}
```