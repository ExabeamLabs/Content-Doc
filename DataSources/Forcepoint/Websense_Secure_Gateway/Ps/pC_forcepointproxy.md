#### Parser Content
```Java
{
Name = forcepoint-proxy
    Vendor = Forcepoint
    Product = Websense Secure Gateway
    Lms = QRadar
    DataType = "web-activity"
    IsHVF = true
    TimeFormat = "epoch"
    Conditions = [ """LEEF:""","""|Forcepoint|Security|""","""|transaction:""","""srcBytes=""" ]
    Fields = [
      """exabeam_endTime=({time}\d{1,100})""",
      """exabeam_host=(.+?@\s{0,100})?({host}[^\s]{1,2000})""",
      """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\ssrcPort=({src_port}\d{1,100})""",
      """\sdstPort=({dest_port}\d{1,100})""",
      """\susrName =(?:\w+:\/+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s{1,100}({user_ou}[^\/]{1,2000})\/({user_fullname}.+?)\s{1,100}([\w\-]{1,2000}=|$)""",
      """\sloginID=(-|(({domain}[^=]{1,2000}?)[\\\/]{1,2000})?({user}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
      """\|transaction:({action}[^\|]{1,2000})""",
      """\smethod=(?:-|({method}[^\s]{1,2000}))""",
      """\ssrcBytes=({bytes_in}\d{1,100})""",
      """\sdstBytes=({bytes_out}\d{1,100})""",
      """\surl=(?:-|({full_url}[^\s"]{1,2000}))""",
      """\surl=(?:-|({protocol}[^:]{1,2000}))""",
      """\surl=(?:[^:]{1,2000}:\/+)({web_domain}[^\/:\s"]{1,2000})""",
      """\surl=(?:-|\w+:\/+[^\/]{1,2000})({uri_path}\/[^?\s"]{1,2000})""",
      """\surl=(?:-|(?=(?)(?:[^?]{1,2000}({uri_query}\?[^\s"]{1,2000}))))""",
      """\suserAgent=(?:-|({user_agent}.+?))\s{1,100}url=""",
      """exabeam_qidName =.+?\s\-\s({category}.+?)\s{1,100}exabeam_""",
      """\scontentType=(?:-|({mime}.+?))\s{1,100}reason=""",
      """\sproxyStatus-code=({result_code}\d{1,100})""",
      """cat=({category_id}\d{1,100})""", 
    ]
  

}
```