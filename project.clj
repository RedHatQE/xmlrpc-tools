(defproject com.redhat.qe/xmlrpc-client-tools "1.0.5"
  :description "Some additions to apache xmlrpc client to handle SSL and Sessions"
  :java-source-path "src" ;; lein1
  :java-source-paths ["src"]
  :dependencies [[org.apache.xmlrpc/xmlrpc-client "3.1.3"]
                 [commons-httpclient/commons-httpclient "3.1"] 
       		 [ca.juliusdavies/not-yet-commons-ssl "0.3.11"]
                 [org.clojars.weissjeffm/httpclient-negotiate "1.0"]]
  :plugins [[lein2-eclipse "2.0.0"]]
  :javac-options ["-target" "1.6" "-source" "1.6"])
