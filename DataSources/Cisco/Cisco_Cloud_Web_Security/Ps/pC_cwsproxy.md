#### Parser Content
```Java
{
Name = cws-proxy
    Vendor = Cisco
    Product = Cisco Cloud Web Security
    Lms = Direct
    DataType = "web-activity"
    IsHVF = true
    TimeFormat = "epoch"
    Conditions = [ """|CISCO|Cloud Web Security|""","""requestMethod="""]
    Fields = [
      """\srt=({time}\d{1,100})""",
      """\sagt=({host}[^\s]{1,2000})""",
      """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\srequest=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:({dest_port}\d{1,100}))?""",
      """\ssrc=(?:0\.0\.0\.0|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
      """\sshost=(?:|({src_host}.+?))\s\w+=""",
      """\sduser=([^\s\\]{1,2000}\\+)?(?:|UNDISCLOSED|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|({user}.+?))\s\w+=""",
      """\sact=(?:|({action}.+?))\s\w+=""",
      """\srequestMethod=(?:|({method}.+?))\s\w+=""",
      """\sout=({bytes_out}\d{1,100})\s\w+=""",
      """\sin=({bytes_in}\d{1,100})\s\w+=""",
      """\|CISCO\|Cloud Web Security\|[^|]{0,2000}\|(?:0|({result_code}\d{1,100}))\|""",
      """\srequest=(?:-|({full_url}\S+))""",
      """\srequest=(?:-|(\w+:\/+)?({web_domain}[^:\/\s]{1,2000}))""",
      """\srequest=(?:-|(({protocol}[^:]{1,2000}))):\/""",
      """\srequest=(?:-|((\w+:\/+)?[^\/]{1,2000}({uri_path}\/.*?)))(\?[^\s]{0,2000})?\srequestMethod=""",
      """\srequest=(?:-|((\w+:\/+)?[^?]{0,2000}({uri_query}\?.*?)))\srequestMethod=""",
      """\srequestClientApplication=(?:-|({user_agent}.+?))\s\w+=""",
      """\scs2=(?:unclassified|({category}.+?))\s\w+=""",
      """\sfileType=(?:-|({mime}.+?))\s\w+=""",
    ]
  

}
```