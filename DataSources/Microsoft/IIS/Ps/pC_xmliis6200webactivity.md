#### Parser Content
```Java
{
Name = xml-iis-6200-web-activity
  Vendor = Microsoft
  Product = IIS
  Lms = Direct
  DataType = "web-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSSZ"
  Conditions = [ """<EventID>6200</EventID>""", """<Provider Name ='Microsoft-Windows-IIS-Logging'""" ]
  Fields = [
    """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d\d\d\d\d\d\dZ)'""",
    """<Computer>({host}[^<]{1,2000}?)<""",
    """<Data Name ='cs-method'>(-|({method}[^<]{1,2000}?))<""",
    """<Data Name ='sc-status'>(-|({result_code}[^<]{1,2000}?))<""",
    """<Data Name ='cs-uri-stem'>(-|\/|({uri_path}[^<]{1,2000}?))<""",
    """<Data Name ='cs-uri-query'>(-|({uri_query}[^<]{1,2000}?))<""",
    """<Data Name ='c-ip'>(::1|127.0.0.1|({src_ip}[A-Fa-f:\d.]{1,2000}?))<""",
    """<Data Name ='s-ip'>(::1|127.0.0.1|({dest_ip}[A-Fa-f:\d.]{1,2000}?))<""",
    """<Data Name ='s-port'>(-|({dest_port}\d{1,200}?))<""",
    """<Data Name ='sc-bytes'>({bytes_out}\d{1,100})""",
    """<Data Name ='cs-bytes'>({bytes_in}\d{1,100})""",
    """<Data Name ='csUser-Agent'>(-|({user_agent}[^<]{1,2000}?))<""",
    """<Data Name ='cs-host'>(-|({web_domain}[^<]{1,2000}?))<""",
    """<Keywords>({outcome}[^<]{1,2000})<""",
    """<Data Name ='s-computername'>(-|({src_host}[^<]{1,2000}?))<""",
    """<Data Name ='cs-username'>(-|(0#\.f\|ww\|)?({user}[^@.<]{1,1000})@({domain}[^.\d<]{1,1000})?)<""",
    """<Data Name ='cs-username'>(-|((0#\.f\|ww\|)|(0#\.w\|))?(((({domain}[^\\]{1,2000})\\)?({user}[^@<]{1,2000}?))|({user_email}[^@]{1,2000}@[^.<]{1,1000}?\.[^<]{1,100})))<""" 
  ]


}
```