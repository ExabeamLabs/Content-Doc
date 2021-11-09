#### Parser Content
```Java
{
Name = vmware-id-manager-activation-token
  DataType = "app-activity"
  Conditions = [ """"objectType""", """vidm""", """"organizationId""", """\"ActivationToken\""""]
}
vmware-id-manager = {
    Vendor = VMware
    Product = VMWare ID Manager (VIDM)
    Lms = Splunk
    TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS z"
    Fields = [
      """"_time":"({time}[^"]{1,2000})"""",
      """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
      """"host":"({host}[^"]{1,2000})"""",
      """"source":"({src_host}[^"]{1,2000})"""",
      """"sourcetype":"({domain}[^"]{1,2000})"""",
      """"objectType\\*":\s{0,100}\\*"({activity}[^\\]{1,2000})\\*"""",
      """"objectId\\*":\s{0,100}\\*"({object_id}[^\\]{1,2000})\\*"""",
      """"objectName\\*":\s{0,100}\\*"({target}[^\\]{1,2000})\\*"""",
      """"deviceType\\*":\s{0,100}\\*"({device_type}[^\\]{1,2000})\\*"""",
      """"success\\*":\s{0,100}\\*"({outcome}[^\\]{1,2000})\\*"""",
      """"resourceType\\*":\s{0,100}\\*"({resource_type}[^\\]{1,2000})\\*"""",
      """"deviceId\\*":\s{0,100}\\*"({user_agent}[^\\]{1,2000})\\*"""",
      """"actorDomain\\*":\s{0,100}\\*"({domain}[^\\]{1,2000})\\*"""",
      """"actorUserName\\*":\s{0,100}\\*"(Not Available|({user_fullname}\w+(\s{1,100}\w+)+)|({user}[^\\]{1,2000}))\\*"""",
      """"uuid\\*":\s{0,100}\\*"({uid}[^\\]{1,2000})\\*"""",
      """"actorUuid\\*":\s{0,100}\\*"({suid}[^\\]{1,2000})\\*"""",
      """"sourceIp\\*":\s{0,100}\\*"({src_ip}[^\\]{1,2000})\\*"""",
      """"authMethods\\*":\s{0,100}\\*"({auth_method}[^\\]{1,2000})\\*"""",
      """"redirectUrl\\*":\s{0,100}\\*"({redirectUrl}[^\\]{1,2000})\\*"""",
      """"failureMessage\\*":\s{0,100}\\*"({failure_reason}[^\\]{1,2000})\\*"""",
      """"message\\*":\s{0,100}\\*"({additional_info}[^\\]{1,2000})\\*"""",
      """"event\\*":\s{0,100}\\*"({event_name}[^\\]{1,2000})\\*"""",
      """"recordAction\\*":\s{0,100}\\*"({operation}[^\\]{1,2000})\\*"""",
      """"oldValues\\*":\s{0,100}\{({old_value}.*?)\}""",
      """"status\\*":\s{0,100}\\*"({status}[^\\]{1,2000})\\*"""",
      """"recordType\\*":\s{0,100}\\*"({object_type}[^\\]{1,2000})\\*"""",
      """"osName\\*":\s{0,100}\\*"({os}[^\\]{1,2000})\\*"""",
      """"osVersion\\*":\s{0,100}\\*"({os_version}[^\\]{1,2000})\\*"""",
      """"osFamily\\*":\s{0,100}\\*"({os_type}[^\\]{1,2000})\\*"""",
      """"machineName\\*":\s{0,100}\\*"({host}[^\\]{1,2000})\\*"""",
      """product=\\*"({app}[^\\"=:]{1,2000})\\*"""",
    ]}
```