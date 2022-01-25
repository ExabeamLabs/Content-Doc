#### Parser Content
```Java
{
Name = ironport-proxy-parser-7
  Product = IronPort Web Security
   Conditions = [ """TCP_MISS/""", """-> - Request Details:""", """xb-accesslog:""" ]

ironport-proxy-2 = {
   Vendor = Cisco
   Lms = Direct
   DataType = "web-activity"
   TimeFormat = "epoch"
   Fields = [
      """(\S{3}\s\d\d \d\d:\d\d:\d\d)\s{1,100}({host}\S+)\s{1,100}\S+\s{1,100}\S+\s{1,100}({time}[\d]{1,2000})(.\d{1,100})\s{1,100}(\d{1,100})\s{1,100}(?:-|({src_ip}[a-fA-F\d.:]{1,2000}))\s{1,100}(?:-|({proxy_action}[^\s\/]{1,2000})\/({result_code}\d{1,100}))\s{1,100}(?:-|({bytes}[^\s]{1,2000}))\s{1,100}(?:-|unknown|({method}[^\s]{1,2000}))\s{1,100}""",
      """(\S{3}\s\d\d \d\d:\d\d:\d\d)\s{1,100}(\S+\s){9}(?:-|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:({dest_port}\d{1,100}))?)\s{1,100}(-|"{0,20}\(Unauthenticated[^"]{1,2000}"{0,20}|"{0,20}((({web_domain}\w+)\\)?({user}[^@\\\s",]{1,2000})[^\s"]{0,2000}"{0,20}))\s(\w+\/)?(-|({=web_domain}\S+))\s(-|({mime}[^\s]{1,2000}))\s.+?<(-|"{0,20}(-|({category}[^,">]{1,2000})))""",
      """(\S{3}\s\d\d \d\d:\d\d:\d\d)\s{1,100}(\S+\s){9}(?:-|({full_url}(({protocol}[^:\\\/\s,"]{1,2000}):[\\\/]{1,2000})?({web_domain}[^\\\/\s:,"]{1,2000})(:({dest_port}\d{1,100}))?({uri_path}\/[^\s\?"]{0,2000})?({uri_query}\?[^"\s]{0,2000})?))\s(-|"{0,20}\(Unauthenticated[^"]{1,2000}"{0,20}|"{0,20}(\w+\\({user}[^@\\\s",]{1,2000})[^\s"]{0,2000}"{0,20}))\s(\w+\/)?(-|({=web_domain}\S+))\s(-|({mime}[^\s]{1,2000}))\s.+?<(-|"{0,20}(-|({category}[^,">]{1,2000})))""",
      """User Agent = "({user_agent}[^"]{1,2000})?"""",
      """Auth-scheme = (NONE|({auth_method}\S+))""",
      """AD Group Memberships = \(.+?\) (-|"({group}[^\]]{1,2000})")\s\]""",
   ]
 
}
```