@load base/frameworks/intel
@load base/files/x509
@load policy/frameworks/intel/seen/where-locations

event x509_ext_subject_alternative_name(f: fa_file, ext: X509::SubjectAlternativeName)
	{
	if ( ext?$dns )
		{
		for ( i in ext$dns )
			Intel::seen([$indicator=DomainTLD::effective_domain(ext$dns[i]),
				$indicator_type=Intel::EFFECTIVE_DOMAIN,
				$f=f,
				$where=X509::IN_CERT]);
		}
	}
