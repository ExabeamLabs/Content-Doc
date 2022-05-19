#### Parser Content
```Java
{
Name = cc-pulsesecure-vpn-close
  DataType = "vpn-end"
  Conditions = [ """"host":""", """"PulseSecure:"""", """ Closed connection to """, """ bytes read """, """ bytes written """ ]
  Fields = ${JuniperParserTemplates.cef-pulsesecure-vpn-events.Fields} [
    """Closed connection to (?:({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w.\-]{1,2000}))""",
    """\safter\s{1,100}({session_duration}\d{1,100})\s{1,100}seconds""",
    """\swith\s{1,100}({bytes_in}\d{1,100})\s{1,100}bytes read""",
	"""\sand\s{1,100}({bytes_out}\d{1,100})\s{1,100}bytes written"""
  ]

cef-pulsesecure-vpn-events = {
  Vendor = Juniper Networks
  Product = Juniper Networks Pulse Secure
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """"host":"({host}[^"]{1,2000})"""",
    """"timestamp":"({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """\- \[({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]\s{1,100}(?:Default Network|Root)::(({domain}[^\\\(]{1,2000})\\)?(System|({user}[^\(]{1,2000}))\(({realm}[^\)]{1,2000})?\)\[({resource}[^\]]{1,2000})?\]""",
    """\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d\s{1,100}\-\s{1,100}({dest_host}[\w\-.]{1,2000})"""
  
}
```