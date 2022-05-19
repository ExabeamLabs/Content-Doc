#### Parser Content
```Java
{
Name = cef-cisco-dns-response-sk4-2
  Conditions = [ """destinationServiceName =Azure""", """dproc=Log Analytics OMS Workspace""", """"QueryType_s":"""", """"Action_s":"Allowed""""]

cef-cisco-dns-response-sk4-template {
  Vendor = Cisco
  Product = Cisco Umbrella
  Lms = Splunk
  DataType = "dns-response"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Fields = [
    """"ResponseCode_s":"({dns_response_code}[^"]{1,2000})"""
    """"Domain_s":"({query}[^"]{1,2000})"""
    """"domain":"({query}[^"]{1,2000})"""
    """"Action_s":"({outcome}[^"]{1,2000})"""
    """"QueryType_s":"({query_type}[^"]{1,2000})"""
    """"Categories_s":"({categories}[^"]{1,2000})"""
    """"InternalIP_s":"({dest_ip}[^"]{1,2000})"""
    """"Identites_s":"([\w\s\.]{1,2000},)?(({user_fullname}\w+\s{1,100}\w+[^",]{1,2000}?) \(({user_email}[^\)@]{1,2000}?@[^\)]{1,2000}?)\))?(,({dest_host}[^\(\)"\s]{1,2000}))?"""
  
}
```