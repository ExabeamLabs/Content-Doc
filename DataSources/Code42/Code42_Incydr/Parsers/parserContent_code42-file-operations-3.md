#### Parser Content
```Java
{
Name = code42-file-operations-3
  Vendor = Code42
  Product = Code42 Incydr
  Lms = Direct
  DataType = "file-operations"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions= [ """KAFKA_CONNECT_SYSLOG: Code42LogCollector,""""]
  Fields = [
    """KAFKA_CONNECT_SYSLOG: Code42LogCollector,.*?,.*?,(|({accesses}[^,]{1,2000})),({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\dZ),.*?,(|({file_path}[^,]{1,2000})),(|({file_name}[^,]{1,2000})),(|({file_type}[^,]{1,2000})),(|({file_category}[^,]{1,2000})),(|({bytes}\d{1,100})),(|({file_owner}[^,]{1,2000})),(|({md5}[^,]{1,2000})),(|({sha256}[^,]{1,2000})),(|({time_created}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)),(|({time_modified}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)),(|({user_email}[^,]{1,2000})),(|({device_id}[^,]{1,2000})),(|({uid}[^,]{1,2000})),(|({host}[^,]{1,2000})),(|({domain}[^,]{1,2000})),(|({src_ip}[^,]{1,2000})),(|({private_ip}[^,]{1,2000})),(|({actor}[^,]{1,2000})),(|({directory}[^,]{1,2000})),(|({log_source}[^,]{1,2000})),(|({url}[^,]{1,2000})),(|({shared}[^,]{1,2000})),(|({shared_with}[^,]{1,2000})|"({=shared_with}[^"]{1,2000}))",(|({file_exposure_changed_to}[^,]{1,2000})),(|({cloud_drive_id}[^,]{1,2000})),(|({detection_source_alias}[^,]{1,2000})),(|({file_id}[^,]{1,2000})),(|({exposure_type}[^,]{1,2000})),(|({process_owner}[^,]{1,2000})),(|({process}[^,]{1,2000})),(|({tab_title}[^,]{1,2000})),,(|({tab_url}[^,]{1,2000})),(|({removable_media_vendor}[^,]{1,2000})),(|({removable_media_name}[^,]{1,2000})),(|({removable_media_serial_number}[^,]{1,2000})),(|({removable_media_capacity}[^,]{1,2000})),(|({removable_media_bus_type}[^,]{1,2000})),(|({removable_media_media_name}[^,]{1,2000})),(|({removable_media_volume_name}[^,]{1,2000})),(|({removable_media_partition_id}[^,]{1,2000})),(|({sync_destination}[^,]{1,2000})),(|({email_dlp_policy_names}[^,]{1,2000})),(|({subject}[^,]{1,2000})),(|({sender}[^,]{1,2000})),(|({email_dlp_from}[^,]{1,2000}))"""
]
  DupFields = ["file_path->file_parent"]
}
```