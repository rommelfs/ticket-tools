t="$1" 
o="$2"
out=`/opt/rt5/bin/rt show $t | grep report.txt|cut -d ":" -f 1`
for a in $out; 
do 
	if [[ $o == "-o" ]]
	then
		/opt/rt5/bin/rt show ticket/$t/attachments/$a/content
		echo
	else
		/opt/rt5/bin/rt show ticket/$t/attachments/$a/content |egrep -v 'User-Agent|Schema-URL|Version|Reported-From|Reported-At|Report-Type|Attachment|Confidence-Level|Dst-Mode|Report-ID|Report-Subcategory|Ip-Protocol-Number|Source-Type|Category|Src-Mode|Source'
		echo
	fi
done;
