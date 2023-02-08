#### Parser Content
```Java
{
Name = hashicorp-app-login-1
  DataType = "app-login"
  Conditions = [ """"type":"response"""", """"auth":{""", """"operation":"""", """"token_type"""", """"vault"""" ]
  Fields = ${HashiCorpParserTemplates.hashicorp-login-activity.Fields} []

hashicorp-login-activity {
    Vendor = HashiCorp
    Product = HashiCorp Vault
    Lms = Splunk
    TimeFormat = "epoch"
    Fields = [
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
      """"username":"(hmac-[^"]{1,2000}|({user}[^"]{1,2000}))""",
      """"time"{1,20}:({time}\d{1,100})""",
      """"remote_address"{1,20}:"{1,20}({src_ip}[^"]{1,2000})""",
      """"operation"{1,20}:"{1,20}({activity}[^"]{1,2000}?)",""",
      """"path"{1,20}:"{1,20}({path}[^"]{1,2000}?)",""",
      """"type"{1,20}:"(hmac-[^"]{1,2000}|({category}[^"]{1,2000}?))",""",
      """"client_token"{1,20}:"{1,20}({client_token}[^"]{1,2000}?)",""",
      """\srequestClientApplication=({app}[^=]{1,2000}?)\s{0,100}\w+=""",
      """"entity_id"{1,20}:"{1,20}({vault_entity_id}[^"]{1,2000}?)",""",
      """"accessor"{1,20}:"{1,20}({accessor}[^"]{1,2000}?)",""",
      """"policies"{1,20}:\[({policies}[^\]]{1,2000}?)\]""",
      """metadata":\{"([^,]{1,2000},){2}"role":"({role}[^"]{1,2000})""",
      """"user-agent":\["({user_agent}[^"]{1,2000})""",
    
}
```