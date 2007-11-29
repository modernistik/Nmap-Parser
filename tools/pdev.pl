#!/usr/bin/perl

=pod

Anthony G Persaud <apersaud@gmail.com> L<http://www.anthonypersaud.com>

Copyright (c) <2007> <Anthony G. Persaud>

MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

=cut


use Data::Dumper;
use File::Basename;

$Data::Dumper::Purity = 1;
use vars qw(%_GLOBALS $ans @_HISTORY $VERSION);
$VERSION = 0.5;


_glob_init();
print "\nPerl-Dev [".($0)." - $VERSION]\n\n";
if(-e $_GLOBALS{cfg}){do "$_GLOBALS{cfg}";print "Loaded $_GLOBALS{cfg} ok.\n";}
print "Use 'our' instead of 'my' for persistent variables.\n";
print "Type ':?' for help.\n\n";



if(scalar @ARGV){
  $_GLOBALS{input} = join ' ', @ARGV;
  print "\t[AutoExe] $_GLOBALS{input}\n";
  exec_src();
}

#Main look for the shell
while(1){
  
  $_GLOBALS{input} ='';
  $_GLOBALS{input} = prompt();
  
  if($_GLOBALS{debug}){
    print "Input: $_GLOBALS{input}\n";
  }


  if( $_GLOBALS{input} =~ s/^://){
    
    parse_scmd($_GLOBALS{input});
    
  } elsif($_GLOBALS{input} =~ s/( )\\ *?$/$1/){
  
    push @{$_GLOBALS{code}}, $_GLOBALS{input}."\n";
    print "[Appending] ".join('',@{$_GLOBALS{code}})."\n" if($_GLOBALS{debug});
    $_GLOBALS{p_type}  = 1;
  
  }
  else {
    
    exec_src();$_GLOBALS{p_type} = 0;
    
  }

}



sub _glob_init {
 %_GLOBALS = (
  input => '',
  scmd => '',
  p_type => 0,
  code => '',
  debug => 0,
  feed => '',
  regex => qr//,
  ans => '',
  dir => dirname($0),
  script => basename($0),
  cfg => dirname($0).'/.pdev'
 );

}

sub exec_src {

  push  @{$_GLOBALS{code}}, $_GLOBALS{input};
  my $_exe = join '', @{$_GLOBALS{code}};
  next if($_exe eq '');
  print "\t[EXE] $_exe\n" if($_GLOBALS{debug});
  $_exe .= ';' if($_exe !~ /;$/);
  push  @_HISTORY, $_exe;
  my @_return = (eval $_exe);
  $_GLOBALS{ans} = $ans = join ' ',@_return;
  print "\n\t[ANS] ",$ans,"\n" if($ans);
  print_err($@);
  @{$_GLOBALS{code}} = ();
   $_GLOBALS{scmd} = '';
  
}


sub print_err {
  my @err = @_;
  print ("\n\t[ERR] ",@err,"\n") if(join('',@err) =~ /\w+/); #if errors
}


sub prompt {
        my $in = '';
        
        if($_GLOBALS{p_type} > 0){ print "  ..> ";}
        #else {             print '[{', $_GLOBALS{hist}++, '}> ';}
        else {             print 'pdev> ';}

        chomp($in = <STDIN>);
        return $in;
}

sub parse_scmd {
   my $scmd = join '',@_;
   my @tokens = split ' ',$scmd;
   my $type = lc(shift @tokens);
   $_GLOBALS{scmd} = $type;
   print "Type: $type\nTokens: ",join(' ',@tokens),"\n" if($_GLOBALS{debug});
  if($type eq  'dump'){_dump($type, @tokens);}
  elsif($type eq  'pop'){_pop($type,@tokens);}
  elsif($type =~  /\d+/){_num($type,@tokens);}
  elsif($type eq 'hist'){_hist($type,@tokens);}
  elsif($type eq 'run'){_run($type,@tokens);}
  elsif($type eq 'feed'){ _feed($type,@tokens);}
  elsif($type eq 'rgx'){ _rgx($type,@tokens);}
  elsif($type eq 'rgxtest'){ _rgxtest($type,@tokens);}
  elsif($type eq 'debug'){ _debug($type,@tokens);}
  elsif($type eq 'rst'){ _rst($type,@tokens);}
  elsif($type eq 'output'){ _output($type,@tokens);}
  elsif($type eq 'sys'){ _sys($type,@tokens);}
  elsif($type eq 'env'){ _env($type,@tokens);}
  elsif($type eq 'help' || $type eq '?'){ _help($type,@tokens);}
  else {print "Unknown special command: $type\n";}

}


#------------------------------------------------------------------------------#
#                            Special Command Functions                         #
#------------------------------------------------------------------------------#

sub _output {
      my $__type = shift;
      my $file = shift || 'pdev.output';
 if(open FILE, ">$file"){

    for my $line (@_HISTORY)
        {
    print "$line\n" if($_GLOBALS{debug});
    print FILE $line."\n";}
    close FILE;
  print "[Output Saved] $file\n";
 }
 else {print "[Err] Could not open output file $file: $!\n";}


}

sub _env {
      my $__type = shift;
      my @__tokens = @_;
      
      print "[GLOBALS]\n";
      for my $key (keys %_GLOBALS){
       printf("\t%10s: %s\n",$key,$_GLOBALS{$key});
      }
      
}


sub _sys {
      my $__type = shift;
      my @__tokens = @_;
      my $__sys_cmd = join ' ', @__tokens;
      $_GLOBALS{input} = 'qx{'.$__sys_cmd.'}';
      if($__sys_cmd eq ''){
     print "[Err] - no system command given $__sys_cmd\n";
  } else {  exec_src(); }
  
}

sub _rst {
  %_GLOBALS = ();$_GLOBALS{ans} = $ans = '';@_HISTORY = ();
  _glob_init();
  print "[Env Reset] - ok\n";
}

sub _debug {
  my $type = shift;
  my $switch = lc(shift);
  if($switch eq 'off'){$_GLOBALS{debug} = 0;print "debugging is off\n";}
  elsif($switch eq 'on') {$_GLOBALS{debug} = 1;print "debugging is on\n";}
  else {print "Choose either 'on' or 'off'. ex. :debug off\n";}
  
  }
  
sub _dump {
      my $__type = shift;
      my @__tokens = @_;
      for my $__var (@__tokens){
      print "Dump: $__var\n" if($_GLOBALS{debug});
      print Data::Dumper->Dump([eval("$__var")],["$__var"])."\n";
      }
}

sub _pop {
  my $__type = shift;
  my @__tokens = @_;

   if(scalar @__tokens == 0){
   @__tokens = ($#_HISTORY);
   }
   
    for my $t (@__tokens){
      print "[Removed History] $_HISTORY[$t]\n";
      $_HISTORY[$t] = undef;
      }

    @_HISTORY = grep {$_ ne undef} @_HISTORY;

}

sub _num {
  my $__type = shift;
  my @__tokens = @_;
  $__type = ($__type+0) || 0;
  $_GLOBALS{input} = $_HISTORY[$__type];
  if($_GLOBALS{input} eq ''){
   print "\n\t[Err] - no command history at $__type\n";
  } else {  exec_src(); }
  
}

sub _hist {
  my $__type = shift;
  my @__tokens = @_;

  print "[History]\n";
  for my $line (0..$#_HISTORY)
    {print "\t[$line] ".$_HISTORY[$line]."\n";}
}


sub _run {
  my $__type = shift;
  my @__tokens = @_;
  print "[Running Feed]\n";
  $_GLOBALS{input} = $_GLOBALS{feed};

  exec_src();
 }
 
sub _feed {
  my $__type = shift;
  my @__tokens = @_;
          $_GLOBALS{feed} = '';
          print "[Feeding] until :end or :run\n";
          my $_curr = $_GLOBALS{input} = '';
          until($_curr =~ /^:end/i || $_curr =~ /^:run/i){
              $_GLOBALS{input} .= $_curr."\n";
              print "\t[...> ";
              chomp($_curr = <STDIN>);
        }
          $_GLOBALS{feed} = $_GLOBALS{input};
          print "[Feed Stored]\n";
          
          if($_curr =~ /^:run/i){

            _run();#runs feed automatically
            }
}

sub _rgx {
  my $__type = shift;
  my @__tokens = @_;
  my $rgx = join '',@__tokens;
  $_GLOBALS{regex} = eval $rgx;
  print "[regex] $_GLOBALS{regex}\n";

}



sub _rgxtest {
  my $__type = shift;
  my @__tokens = @_;

  my $__test_str = join '',@__tokens;
  print "Regex Stored: $_GLOBALS{regex}\n" if($_GLOBALS{debug});
  print "Test String : $__test_str\n" if($_GLOBALS{debug});

  if($__test_str =~ $_GLOBALS{regex}){
  print "\n[REGEX MATCH] OK.\n\n";
  print "Prematch   : $`\n";
  print "Match      : $&\n";
  print "Postmatch  : $'\n";
  print "Lastmatch  : $+\n";


  print "[Captured Matches]\n";
  for my $m (1..9){
  print "\t[\$$m]  : ".${$m}."\n" if(${$m} ne '');
  }
  
  } else {
   print "\n[REGEX MATCH] NONE.\n\n";
  }
  

}


sub _help {
  my $__type = shift;
  my @__tokens = @_;
  
print q{
[Special Commands]
  All special commands must be be prefixed with ':', for example ':help'.

  dump    - Data::Dump of a variable
              :dump $var
  debug   - turns debugging 'on' or 'off' (use 'on' or 'off' as parameters)
              :debug 'on' #turns debuggin on
  rgx     - store regular expression
              :rgx qr/\w+_(\w+)/i
  env     - prints the current environment variables
  rgxtest - tests the regex in rgx against text
              :rgxtest my_test
  feed    - starts storing line-by-line perl code and stores it.
  end     - use to end the feeding process of feed.
  run     - executes the code stored by feed.
  pop     - removes the last code line that has been stored.
            If number is given, it removes that entry from the history.
              :pop 3 4 #removes entry 3 and 4 from history.
  [num]  - runs the command in history denoted by num.
              :1 #runs command in history 1
  hist    - lists command history.
  rst     - resets all internal variables (cleans the shell)
  sys     - run a system command using ``;
  log     - outputs history information to file.
              :out script.txt
  help    - this help information
  ?       - same thing as 'help'
  
  
[Special Variables]
    [Do not use any variables with underscore '__' (double underscore)]
    
    $ans      - contains the results of the return value of last operation
                  pdev> 4+5
                    [ANS] 9
                  pdev> $ans + 1
                    [ANS] 10
    @_HISTORY - contains the listing of history commands
    %_GLOBALS - contains the global environment variables

    
[Special Files]

  .pdev       - if this file is located in the current directory, pdev will
                'eval' the file. This is usefule to load regularly used
                libraries, variables or configurations.
                
[Extras]
1. Use 'our' instead of 'my' for persistent variables.
2. You can also auto execute command line strings before entering the shell:

   pdev.pl print(5+4);
      Perl-Dev [U:\pdev.pl]
      [AutoExe] print(5+4)
      9
   pdev>
  

Anthony G Persaud <apersaud@gmail.com> L<http://www.anthonypersaud.com>

Copyright (c) <2007> <Anthony G. Persaud>

MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

};

}


