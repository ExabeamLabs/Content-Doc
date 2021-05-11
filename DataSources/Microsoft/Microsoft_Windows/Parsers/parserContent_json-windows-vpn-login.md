#### Parser Content
```Java
{
Name = json-windows-vpn-login
  DataType = "vpn-start"
  Conditions = [ """"service":"vpn"""", """Virtual-Server""" ]
  Fields = ${WinParserTemplates.json-windows-events.Fields}[
    """"User-Name":"(({user_email}[^"@]+@[^"@]+)|({user}[^"]+))""",
    """"Packet-Type":"({action}[^"]+)""",
    """"Client-IP-Address":"({src_ip}[a-fA-F\d.:]+)""",
    """"Client-Shortname":"({src_host}[^"]+)""",
    """"NAS-IP-Address":"({src_ip}[a-fA-F\d.:]+)""",
    """"Framed-IP-Address":"({dest_ip}[a-fA-F\d.:]+)""",
    """"hostname":"({host}[^"]+)""",
    """"status":"({outcome}[^"]+)""",
    """"realm":"({realm}[^"]+)""",
  ]
}
json-windows-events = {
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """"@timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """"service":".+?","host":"({host}[^"]+)""",
    """"host":"({host}[^"]+)","authentication""",
    """"host":"({host}[^"]+)","service":"""",
    """"host":"({host}[^"]+)","ad"""",
    """"host":"({host}[^"]+)","index"""",
    """"user":\{[^\}]*?"uid":"({user}[^"@]+)""",
    """"country_code2":"({src_external_country}[^"]+)""",
    """"domain":"({domain}[^"]+)""",
    """"source":\{([^\}]*?\{([^\}]*?\{[^\{\}]*?\})*[^\}]*?\})*[^\}]*?"host":"({src_host}[^"]+)""",
    """"source":\{([^\}]*?\{([^\}]*?\{[^\{\}]*?\})*[^\}]*?\})*[^\}]*?"ipv4":"({src_ip}[a-fA-F\d.:]+)""",
    """"destination":\{([^\}]*?\{([^\}]*?\{[^\{\}]*?\})*[^\}]*?\})*[^\}]*?"host":"({dest_host}[^"]+)""",
    """"destination":\{([^\}]*?\{([^\}]*?\{[^\{\}]*?\})*[^\}]*?\})*[^\}]*?"ipv4":"({dest_ip}[a-fA-F\d.:]+)""",
    """"logon-type":({logon_type}\d{1,100})""",
    """"logon-id":"({logon_id}[^"]+)""",
    """"event-type":"({outcome}[^"]+)""",
    """"event-id":({event_code}\d{1,100})""",
    """"message":"({event_name}[^"]+)""",
    """"user-sid":"({user_sid}[^"]+)""",
    """"status":"({result_code}[^"]+)""",
    """"service-name":"({dest_host}[^"]+\$)""",
    """"service-name":"({service_name}[^"]+)"""
  ]

```