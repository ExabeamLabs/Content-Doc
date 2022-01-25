#### Parser Content
```Java
{
Name = websense-proxy-1
    Vendor = Forcepoint
    Product = Websense Secure Gateway
    Lms = Direct
    DataType = "web-activity"
    IsHVF = true
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """|Websense|Security|""","""|transaction:""","""srcBytes=""" ]
    Fields = [
      """exabeam_endTime=({time}\d{1,100})""",
      """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
      """\d{1,2}:\d{1,2}:\d{1,2}\s{1,100}({host}[^\s]{1,2000})\s{0,100}LEEF:""",
      """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\ssrcPort=({src_port}\d{1,100})""",
      """\sdstPort=({dest_port}\d{1,100})""",
      """\susrName =(-|(?!LDAP:)({user}.+?))\s{1,100}\w+=""",
      """\susrName =LDAP:\/\/\S+\s{1,100}({user_ou}[^\/]{1,2000}?)\/({user_fullname}.+?)\s{1,100}\w+=""",
      """\|transaction:({action}[^\|]{1,2000})""",
      """\smethod=(?:-|({method}[^\s]{1,2000}))""",
      """\ssrcBytes=({bytes_in}\d{1,100})""",
      """\sdstBytes=({bytes_out}\d{1,100})""",
      """\scontentType=(?:-|({mime}[^=]{1,2000})(;.*)?)\s{1,100}reason=""",
      """\sproxyStatus-code=({result_code}\d{1,100})""",
      """\scat=({category_id}\d{1,100})""",
      """exabeam_qidName =.+?\s\-\s({category}[^=]{1,2000})\s{1,100}exabeam_""",
      """\suserAgent=(?:-|({user_agent}.+?))\s{1,100}\w+=""",
      """\surl=(?:-|({full_url}[^\s"]{1,2000}))""",
      """\surl=(?:-|({protocol}[^:]{1,2000}))""",
      """\surl=(?:[^:]{1,2000}:\/+)({web_domain}[^\/:\s]{1,2000})""",
      """\surl=(?:-|\w+:\/+[^\/]{1,2000})({uri_path}\/[^?\s]{1,2000})""",
      """\surl=(?:-|(?=(?)(?:[^?]{1,2000}({uri_query}\?[^\s"]{1,2000}))))""",
    ]
  

}
```