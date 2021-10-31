
IFS_old=$IFS
IFS=$'\n'
for file in `ls ./dataset_test34`
do
    renamef='a'$file
    var=$(echo $renamef | sed s/[[:space:]]/_/g)  #去处文件名中的空格
    #echo $var
    mv $file $var
done
IFS=$IFS_old

