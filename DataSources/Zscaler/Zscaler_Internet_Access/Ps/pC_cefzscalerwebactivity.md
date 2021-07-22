#### Parser Content
```Java
{
Name = cef-zscaler-web-activity
  Vendor = Zscaler
  Product = Zscaler Internet Access
  Lms = ArcSight
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """|Zscaler|NSSWeblog|""", """requestClientApplication=""", """act=""" ]
  Fields = [
    """\srt=({time}\d{1,100})""",
    """\srt=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
    """\d\d:\d\d:\d\d ({host}\S+) CEF:""",
    """\sdvchost=({host}[\w\-.]{1,2000})\s{0,100}(\w+=|$)""",
    """\ssrc=({src_ip}[a-fA-F:\d.]{1,2000})\s{0,100}(\w+=|$)""",
    """\sdst=({dest_ip}[a-fA-F:\d.]{1,2000})\s{0,100}(\w+=|$)""",
    """([^\|]{0,2000}\|){5}({action}[^\|]{1,2000})""",
    """(\s|\|)act=({action}[^=]{1,2000}?)\s{0,100}(\w+=|$)""",
    """\ssuser=(NA|None|\$NULL|(?![^\s]{1,2000}@[^\s]{1,2000})({user}[^=]{1,2000}?))\s{0,100}(\w+=|$)""",
    """\ssuser=({user_email}({user}[^\s@]{1,2000})@[^\s]{1,2000})\s{0,100}(\w+=|$)""",
    """\sapp=({protocol}[^=]{1,2000}?)\s{0,100}(\w+=|$)""",
    """\srequestProtocol=({protocol}[^=]{1,2000}?)\s{0,100}(\w+=|$)""",
    """\scs4=(None|({ransomware_name}[^=]{1,2000}?))\s{0,100}(\w+=|$)""",
    """\srequest=({full_url}[^\s]{1,2000}?)\s{1,100}(\w+=|$)""",
    """\srequest=(\w+:\/{2})?[^\/]{1,2000}({uri_path}\/[^?\s]{1,2000})(\?\S+)?\s{1,100}(\w+=|$)""",
    """\srequest=(\w+:\/+)?[^|\/:]{1,2000}(:\d{1,100})?[^|?]{1,2000}({uri_query}\?[^\s]{1,2000})""",
    """\srequest=(?:[^:?]{1,2000}:\/+)?({web_domain}[^\/:\s]{1,2000})""",
    """\srequestMethod=(NA|({method}[^=]{1,2000}?))\s{0,100}(\w+=|$)""",
    """\srequestClientApplication=([uU]nknown|({user_agent}[^=]{1,2000}?))\s{0,100}(\w+=|$)""",
    """\scn1=({risk_level}\d{1,100})""",
    """\sout=({bytes_in}\d{1,100})""",
    """\sin=({bytes_out}\d{1,100})""",
    """\scat=({category}[^=]{1,2000}?)\s{0,20}\w+=""",
    """\sfileType=(None|({mime}[^=]{1,2000}?))\s{0,100}(\w+=|$)""",
    """\soutcome=({result_code}\d{1,100})""",
    """\sreason=({proxy_action}[^=]{1,2000}?)\s{0,100}(\w+=|$)""",
    """\scs1=({department}[^=]{1,2000}?)\s{0,100}(\w+=|$)""",
    """\scs2=({categories}[^=]{1,2000}?)\s{0,100}(\w+=|$)""",
    """\scs5=(None|({threat_name}[^=]{1,2000}?))\s{0,100}(\w+=|$)""",
    """\scs6=(None|({dlp_engine}[^=]{1,2000}?))\s{0,100}(\w+=|$)""",
    """sourcehost=(NA|None|\$NULL|({src_host}[^=]{1,2000}?))\s{1,100}destinationhost=""",
    """devicehostname=({src_host}[^\s"]{1,2000}?)\s{0,100}(\w+=|$)""",
    """ZscalerNSSWeblogDLPDictionaries=(None|({web_log_dict}[^=]{1,2000}?))\s{0,100}([\w.]{1,2000}=|$)"""
  ]
  DupFields = ["ransomware_name->threat_category", "risk_level->suspicious_content"]
}
```