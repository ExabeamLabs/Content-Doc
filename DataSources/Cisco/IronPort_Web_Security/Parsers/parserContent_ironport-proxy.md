#### Parser Content
```Java
{
Name = ironport-proxy
    Vendor = Cisco
  Product = IronPort Web Security
    Lms = Direct
    DataType = "web-activity"
    IsHVF = true
    TimeFormat = "epoch"
    Conditions = [ """|CISCO|IronPort Web Security Appliance|""","""categorySignificance="""]
    Fields = [
      """\srt=({time}\d{1,100})""",
      """exabeam_host=({host}[^\s]{1,2000})""",
      """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sdvchost=({host}[^\s]{1,2000})""",
      """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\srequest=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:({dest_port}\d{1,100}))?""",
      """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sduser=(({domain}[^\s\\]{1,2000})\\+)?({user}.+?)\s\w+=""",
      """\sact=(?:NONE|({proxy_action}.+?))\s\w+=""",
      """\scategoryOutcome=\/({action}.+?)\s\w+=""",
      """\srequestMethod=({method}.+?)\s\w+=""",
      """\sout=({bytes_out}\d{1,100})\s\w+=""",
      """\sin=({bytes_in}.+?)\s\w+=""",
      """\|CISCO\|IronPort Web Security Appliance\|[^|]{0,2000}\|({result_code}.+?)\|""",
      """\sdhost=(?:-|({web_domain}.+?))\s\w+=""",
      """\smsg=(?:-|(\w+\s{1,100}({protocol}[^:]{1,2000}))):\/\/""",
      """\srequest=(-|({full_url}\S+))""",
      """\srequest=(?:-|(\w+:\/+[^\/]{1,2000}\/({uri_path}.+?)))(\?.+?)?\srequestMethod=""",
      """\smsg=(?:-|(\w+\s{1,100}\w+:\/+[^?]{1,2000}({uri_query}\?.+?)))\sin=""",
      """\scs2=(?:-|({user_agent}.+?))\s\w+=""",
      """\scs3=(?:ns|({score}.+?))\s\w+=""",
      """\scs4=.+?(KHTML,)?([^,]{0,2000}
```