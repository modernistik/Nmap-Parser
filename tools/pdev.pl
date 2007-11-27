#!/usr/bin/perl

use Data::Dumper;
use vars qw($_hist $_src @_code @_return @_HISTORY @_RETURN_HIST $_more $_ans $_feed);
$Data::Dumper::Purity = 1;

print "\nDevShell [apersaud\@qualcomm.com]\n\n";
if(-e ".pdev"){do ".pdev";print "Loaded .pdev\n";}
print "Do not use 'my' for variable declarations - unless using :feed\n";
print "To quit - use 'exit'\n";

 $_src = '';
 @_code = ();
 @_return = "";
 @_HISTORY = ();
 @_RETURN_HIST = ();
 $_more = 0;
 $_ans = '';
 $_feed = '';
#$SIG{$_} = 'IGNORE' for keys %SIG;

while(1){

prompt($_more);
$_more = 0;
$_src = '';
chomp($_src = <STDIN>);

if($_src =~ /^:/){

  if($_src =~    s/^:dump//i){print Data::Dumper->Dump([eval($_src)]);}
  elsif($_src =~  /^:pop/i){my $_line = pop @_code;print "[Removed] $_line\n";}
  elsif($_src =~ s/^:(\d+)/$1/i){ $_src = ($_src+0) || 0; $_src = $_HISTORY[$_src]; run_code();}
  elsif($_src =~  /^:hist/i){

    print "[History]\n";

    for my $_line (0..$#_HISTORY){print "\t[$_line] ".$_HISTORY[$_line]."\n";}

    }
  elsif($_src =~ /^:restart/i){ print "[Restarting]\n";exec "$0";}
  elsif($_src =~ /^:runfeed/i){ $_src = $_feed; $_hist++; run_code(); }
  elsif($_src =~ /^:feed/i){$_feed='';
    print "[Feeding] until :end\n";$_feed = $_src;
    my $_curr = $_src = '';
    while($_curr !~ /^:end/i){
    $_src .= $_curr;
    print "\t[Feeding]> ";
    chomp($_curr = <STDIN>);
  }
  $_feed = $_src;
  print "[Feed Stored]\n";
  }

  else {print "[Command Captured] - not implemented\n";  }

  $_hist--;
}
elsif($_src =~ / \\$/){
  $_src =~ s/\\$//;
  push @_code, $_src;
  print "\n[Appending] $_src\n";
  $_more = 1;
} else {

 if($_src eq ''){$_hist--;}
 else {run_code();}
 }


}


sub run_code {
  push @_code, $_src;
  my $_exe = join '',@_code;
  push @_HISTORY, $_exe;
  print "\n[EXE] $_exe\n";
  @_return = (eval $_exe);
  $_ans = join '',@_return;
  print "\n[ANS] ",$_ans,"\n" if($_ans);
  print_err($@);
  @_code = ();
}


sub print_err {
  my @err = @_;
  print (@err,"\n") if(@err > 0); #if errors
}


sub prompt {
     my $type = shift;
        if($type > 0){ print "\n", '   [', $_hist, ']> ';}
        else {             print "\n", 'pdev[', $_hist++, ']> ';}

   }
   

