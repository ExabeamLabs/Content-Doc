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
    """"index":"[^\{\}]{0,2000}?"host":"({host}[\w\-.]{1,2000})""",
    """"host":"({host}[\w\-.]{1,2000})"[^\{\}]{0,2000}?"index":"""",
    """"status":"({outcome}[^"]{1,2000})""",
    """"destination":\{.*?"ipv4":"({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """"destination":\{.*?"host":"({dest_host}[\w\-.]{1,2000})""",
    """"source":\{.*?"ipv4":"({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """"source":\{.*?"host":"({src_host}[\w\-.]{1,2000})""",
    """"user":\{?[^\{\}]{0,2000}?"realm":"({realm}[^"\s]{1,2000})"""",
    """"user":\{?[^\{\}]{0,2000}?"uid":"({user}[^"\s]{1,2000})"""",
    """"message":"({additional_info}[^"]{1,2000})""",
    """"domain":"({domain}[^"\s]{1,2000})""",
  ]
}
```