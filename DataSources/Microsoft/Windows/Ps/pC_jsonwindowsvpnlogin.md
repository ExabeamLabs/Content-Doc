#### Parser Content
```Java
{
Name = json-windows-vpn-login
  DataType = "vpn-start"
  Conditions = [ """"service":"vpn"""", """Virtual-Server""" ]
  Fields = ${WinParserTemplates.json-windows-events.Fields}[
    """"User-Name":"(({user_email}[^"@]{1,2000}@[^"@]{1,2000})|({user}[^"]{1,2000}))""",
    """"Packet-Type":"({action}[^"]{1,2000})""",
    """"Client-IP-Address":"({src_ip}[a-fA-F\d.:]{1,2000})""",
    """"Client-Shortname":"({src_host}[^"]{1,2000})""",
    """"NAS-IP-Address":"({src_ip}[a-fA-F\d.:]{1,2000})""",
    """"Framed-IP-Address":"({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """"hostname":"({host}[^"]{1,2000})""",
    """"status":"({outcome}[^"]{1,2000})""",
    """"realm":"({realm}[^"]{1,2000})""",
  ]

json-windows-events = {
  Vendor = Microsoft
  Product = Windows
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """"@timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """"service":".+?","host":"({host}[^"]{1,2000})""",
    """"host":"({host}[^"]{1,2000})","authentication""",
    """"host":"({host}[^"]{1,2000})","service":"""",
    """"host":"({host}[^"]{1,2000})","ad"""",
    """"host":"({host}[^"]{1,2000})","index"""",
    """"user":\{[^\}]{0,2000}?"uid":"({user}[^"@]{1,2000})""",
    """"country_code2":"({src_external_country}[^"]{1,2000})""",
    """"domain":"({domain}[^"]{1,2000})""",
    """"source":\{([^\}]{0,2000}?\{([^\}]{0,2000}?\{[^\{\}]{0,2000}?\})*[^\}]{0,2000}?\})*[^\}]{0,2000}?"host":"({src_host}[^"]{1,2000})""",
    """"source":\{([^\}]{0,2000}?\{([^\}]{0,2000}?\{[^\{\}]{0,2000}?\})*[^\}]{0,2000}?\})*[^\}]{0,2000}?"ipv4":"({src_ip}[a-fA-F\d.:]{1,2000})""",
    """"destination":\{([^\}]{0,2000}?\{([^\}]{0,2000}?\{[^\{\}]{0,2000}?\})*[^\}]{0,2000}?\})*[^\}]{0,2000}?"host":"({dest_host}[^"]{1,2000})""",
    """"destination":\{([^\}]{0,2000}?\{([^\}]{0,2000}?\{[^\{\}]{0,2000}?\})*[^\}]{0,2000}?\})*[^\}]{0,2000}?"ipv4":"({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """"logon-type":({logon_type}\d{1,100})""",
    """"logon-id":"({logon_id}[^"]{1,2000})""",
    """"event-type":"({outcome}[^"]{1,2000})""",
    """"event-id":({event_code}\d{1,100})""",
    """"message":"({event_name}[^"]{1,2000})""",
    """"user-sid":"({user_sid}[^"]{1,2000})""",
    """"status":"({result_code}[^"]{1,2000})""",
    """"service-name":"({dest_host}[^"]{1,2000}\$)""",
    """"service-name":"({service_name}[^"]{1,2000})""",
    """auth-package":"({auth_package}[^"]{1,2000})"""",
    """workstation-name":"(-|({src_host_windows}[^"]{1,2000}))""""
  
}
```