#### Parser Content
```Java
{
Name = websense-proxy
  Conditions = [ """|Websense|Security|""","""cs3Label=ContentType"""]
  Fields = ${WPParserTemplates.wp-web-activity.Fields} [
      """\ssuser=(-|(?!LDAP:)({user}.+?))\s\w+=""",
      """\ssuser=LDAP:\/\/\S+\s{1,100}({user_ou}[^\/]{1,2000}?)\/(System|({user_fullname}[^,]{1,2000}?))\s{1,100}\w+=""",
      """\ssuser=LDAP:\/\/\S+\s{1,100}({user_ou}[^\/]{1,2000}?)\/({user_lastname}[^,\\]{1,2000}?)\\?,\s{0,100}({user_firstname}[^\\,]{1,2000}?)\s{1,100}\w+=""",
      """\sdhost=(?:-|({web_domain}.+?))\s\w+=""",
      """\scs4=({category}.+?)\s{1,100}\w+=""",
      """\|Websense\|([^|]{1,2000}\|){2}({category_id}[^|]{1,2000})""",
  ]
  DupFields = [ "user->orig_user" ]
  
wp-web-activity = {
  Vendor = Forcepoint
  Product = Websense Secure Gateway
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "epoch"
  Fields = [
      """\srt=({time}\d{1,100})""",
      """\sin=({bytes_in}.+?)\s\w+=""",
      """\sout=({bytes_out}\d{1,100})\s\w+=""",
      """\sact=({action}.+?)\s\w+=""",
      """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sspt=({src_port}\d{1,100})\s\w+=""",
      """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sdpt=({dest_port}\d{1,100})\s\w+=""",
      """\srequest=(-|({full_url}(({protocol}[^:\\\/\s,"]{1,2000}):[\\\/]{1,2000})?({web_domain}[^\\\/\s:,"]{1,2000})(:\d{1,100})?({uri_path}\/[^\s\?"]{0,2000})?({uri_query}\?[^"\s]{0,2000})?))\s{1,100}(\w+=|$)""",
      """\srequestUrlFileName =(?:(-|)|({uri_path}.+?))\s\w+=""",
      """\srequestUrlQuery=(?:-|({uri_query}.+?))\s\w+=""",
      """\srequestMethod=({method}.+?)\s\w+=""",
      """\srequestClientApplication=(?:-|({user_agent}.+?))\s\w+=""",
      """\scs3=(?:-|({mime}.+?))\s\w+=""",
      """\s(requestProtocol|app)=(?:-|({protocol}.+?))\s\w+=""",
      """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sdvchost=({host}[^\s]{1,2000})"""
  
}
```