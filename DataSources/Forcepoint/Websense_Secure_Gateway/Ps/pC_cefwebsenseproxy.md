#### Parser Content
```Java
{
Name = cef-websense-proxy
  Conditions = [ """|Websense|Web Security|""","""CEF:""", """in=""", """out=""", """cs3Label=ContentType"""]
  Fields = ${WPParserTemplates.wp-web-activity.Fields} [
      """\scat=({category_id}\d{1,100})""",
      """\sreason=({reason}.+?)\s{1,100}\w+=""",
      """\sshost=({src_host}[^\s]{1,2000})\s""",
      """\ssuser=({user_fullname}.+?)\s{1,100}\w+=""",
      """\ssuid=LDAP:\/\/\S+\s{1,100}({user_ou}[^\/]{1,2000}?)\/.+?\s{1,100}\w+=""",
      """\scs6=(?:-|({web_domain}.+?))\s\w+="""
  ]
  
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
      """requestClientApplication=[^=]{0,2000}?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)[^=]{0,2000}?\s{1,100}(\w+=|$)""",
      """requestClientApplication=[^=]{0,2000}?({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^=]{0,2000}?\s{1,100}(\w+=|$)""",
      """\scs3=(?:-|({mime}.+?))\s\w+=""",
      """\scs6=(.*?)({top_domain}[^.\s\/:]{1,2000}(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|tr))+\s\w+=).+?)\s\w+=""",
      """\s(requestProtocol|app)=(?:-|({protocol}.+?))\s\w+=""",
      """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sdvchost=({host}[^\s]{1,2000})"""
  
}
```