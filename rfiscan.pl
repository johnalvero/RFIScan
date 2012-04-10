#!/usr/bin/perl
#
# PHP RFI Vulnerability Scanner
# John Homer H Alvero
# Feb. 1, 2010

my $file = '';
my @filelist = ();
my $txt_folder = $ARGV[0] . '/';
my $check_declarations = 1;
my $found = 0;

&check_folders($txt_folder);

if ($found) {
        print "RFI Vulnerability Found!\n";
} else {
        print "No vulnerability found\n";
}


# SUB(s)

sub check_folders {
   my($dir) = @_;
   local (*FOLDER);
   my @fileVars = ();
   my $lineVar;

   my(@subfiles, $file, $specfile);
   opendir(FOLDER, $dir) or die "cannot open $dir";

   print "opening folder $dir \n";

   @subfiles = readdir(FOLDER);
   closedir(FOLDER);

   foreach $file (@subfiles) {
      $specfile = $dir .  $file;
      if (-f $specfile && $file =~ m/\S+\.php/) {

      open FILE, "<", $specfile or die $!;
      my $line_ctr = 0;
      print "in file $specfile\n";
      while (< FILE >) {
         $line_ctr++;
         if ($_ =~ m/^(\s|\t)*(include|include\_once|require|require\_once)\s*\(?\s*\$\w*\s*\)?/) {

            my ($line1,$line2,$line3) = $_ =~ m/^(\s|\t)*(include|include\_once|require|require\_once)\s*\(?\s*(\$\w+)\s*\)?/;


            if ($check_declarations) {
              if (!(chomp($line2) !~ @fileVars)) {
                print "Line No: $line_ctr $_";
                $found = 1;
              }

            } else {
                print "Line No: $line_ctr $_";
                $found = 1;
            }
          }

         if ($_ =~ m/^(\s*\$\S*\s*\=\s*)/i) {
            my ($lineVar) = $_ =~ m/^(\s*\$\S*)/i;
            push(@fileVars,$lineVar);
         }
      }
      close(FILE);
      @fileVars = ();
      } elsif (-d $specfile) {
        if ($specfile !~ m/\S+\.$/) {
         &check_folders($specfile . "\/");
      }
      }#if
   }#for
}#sub
