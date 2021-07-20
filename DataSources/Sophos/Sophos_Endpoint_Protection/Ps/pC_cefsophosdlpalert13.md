#### Parser Content
```Java
{
Name = cef-sophos-dlp-alert-13
  Vendor = Sophos
  Product = Sophos Endpoint Protection
  Lms = ArcSight
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [  """CEF:""", """Event::Endpoint::DataLossPreventionAutomaticallyAllowed""", """group=DATA_LOSS_PREVENTION""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """"location":"({host}[\w\-.]{1,2000})"""",
    """"when":"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """"type":"({alert_type}Event[^"]{1,2000})""",
    """"severity":"({alert_severity}[^"]{1,2000})""",
    """"id":"({alert_id}[^"]{1,2000})""",
    """"location":"({src_host}[^"]{1,2000})""",
    """"name":\s{0,100}"({alert_name}.+?)\s{1,100}(\w+:)"""
    """"name":\s{0,100}"({additional_info}[^"]{1,2000})"""
    """"name".+?Username:\s{0,100}(({domain}[^\\]{1,2000})\\+)?({user}[^\s\\]{1,2000})\s""",
    """"name".+?Rule names:\s{0,100}′({rule}[^′]{1,2000})""",
    """"name".+?User action:\s{0,100}({activity}.+?)\s{1,100}(\w+\s{1,100}\w+:)""",
    """"name".+?Application Name:\s{1,100}({app}.+?)\s{1,100}Data Control action:""",
    """"name".+?Data Control action:\s{0,100}({outcome}[^\s]{1,2000})\s""",
    """"name".+?File type:\s{0,100}({file_type}.+?)\s{1,100}File size:\s{0,100}({bytes}\d{1,100})\s""",
    """"name".+?Source path:\s{0,100}({target}.+?)\s{0,100}(\w+\s{1,100}\w+:|")"""
  ]
}
```