#### Parser Content
```Java
{
Name = azure-blobegress-json
  Vendor = Microsoft
  Product = Microsoft Azure
  Lms = Direct
  DataType = "azure-metrics"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """metricName":"Egress"""", """ApiName":"GetBlob""" ]
  Fields = [
    """"{1,20}count"{1,20}:\s{0,100}({blob_count}[^",\s]{1,2000})""",
    """"{1,20}total"{1,20}:\s{0,100}({bytes_total}[^",\s]{1,2000})""",
    """"{1,20}minimum"{1,20}:\s{0,100}({min_blob_size}[^",\s]{1,2000})""",
    """"{1,20}maximum"{1,20}:\s{0,100}({max_blob_size}[^",\s]{1,2000})""",
    """"{1,20}resourceId"{1,20}:\s{0,100}"{1,20}({resource}[^"]{1,2000})"{1,20}""",
    """"{1,20}time"{1,20}:\s{0,200}"{1,20}(\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}.\d{1,100}Z?)"{1,20}""",
    """"{1,20}metricName"{1,20}:\s{0,100}"{1,20}({metric_type}[^"]{1,2000})"{1,20}""",
    """"{1,20}AccountResourceId"{1,20}:\s{0,100}"{1,20}({storage_account_id}[^"]{1,2000}\/({storage_account}[^,"]{1,2000}))"{1,20}""",
    """"{1,20}ApiName"{1,20}:\s{0,100}"{1,20}({metric_name}[^"]{1,2000})"{1,20}""",
    """"{1,20}average"{1,20}:\s{0,100}({avg_blob_size}[^",\s]{1,2000})"""
  ]


}
```