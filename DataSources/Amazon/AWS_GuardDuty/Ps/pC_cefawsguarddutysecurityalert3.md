#### Parser Content
```Java
{
Name = cef-aws-guardduty-security-alert-3
  Conditions = [ """CEF:""", """destinationServiceName =AWS""", """"awsApiCallAction":""", """"serviceName":"guardduty"""", """"type":"Trojan:EC2/DGADomainRequest.B"""" ]
  Fields = ${AwsGuardDutyParserTemplates.cef-aws-guardduty-security-alert-template.Fields} [
    """platform":[^=]{1,2000}?"key":"Name","value":"({host}[^"]{1,2000})"(,|\}|\])""",
  ]

cef-aws-guardduty-security-alert-template = {
    Vendor = Amazon
    Product = AWS GuardDuty
    Lms = Splunk
    DataType = "alert"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ" 
    Fields = [
      """exabeam_host=({host}[\w.\-]{1,2000})""",
      """"createdAt":\s{0,100}"({time}\d{4}-\d{2}-\d{2}T(\d{2}:){2}\d{2}\.\d{1,100}Z)",""",
      """"ipAddressV4":\s{0,100}"({src_ip}(\d{1,3}\.){3}\d{1,3})"""",
      """"title":"({event_name}[^"]{1,2000})",""",
      """"type":"({alert_type}[^"]{1,2000}):({alert_name}[^"]{1,2000})",""",
      """"severity":\s{0,100}({alert_severity}[\d.]{1,2000}),""",
      """"region":\s{0,100}"({region}[^"]{1,2000}?)",""",
      """"description":\s{0,100}"({additional_info}[^"]{1,2000}?)",""",
      """"accountId":\s{0,100}"({account_id}[^"]{1,2000}?)","""
      """domain":"({domain}[^"]{1,2000})"""",
      """resource":[^}]{1,2000}principalId":\s{0,100}"([^},]{1,2000}?(:({user_email}[^@]{1,2000}@[^},]{1,2000}))?)","userName":\s{0,100}"({user}[^},]{1,2000}?)","userType":\s{0,100}"({user_type}[^},]{1,2000}?)"""",
      """key":"PrincipalId","value":"([^:]{1,2000}:)?({user_email}[^@]{1,2000}@[^},"]{1,2000}?)"""",
      """"resourceType":\s{0,100}"({resource_type}[^"]{1,2000})"""",
      """S3BucketDetails:\s{0,100}\[\{Arn:\s{0,100}({object}[^,]{1,2000}),Name:""",
    
}
```