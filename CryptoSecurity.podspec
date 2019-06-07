Pod::Spec.new do |spec|

  spec.name         = 'CryptoSecurity'
  spec.version      = '1.2'

  spec.license      = { :type => 'MIT', :file => 'LICENSE.txt' }

  spec.authors      = { 'Kevin Wooten' => 'kevin@outfoxx.io' }

  spec.homepage     = 'https://github.com/outfoxx/cryptosecurity'

  spec.summary      = 'Crypto & Securty framework wrappers for Swift, along with ASN.1 and X.509 utilities.'
  spec.source       = { :git => 'https://github.com/outfoxx/CryptoSecurity.git', :tag => '1.2' }
  spec.source_files = 'Sources/*.{h,m,swift}'
  spec.framework    = 'Security'

  spec.swift_versions = ['5.0']

  spec.ios.deployment_target = '8.0'
  spec.osx.deployment_target = '10.10'
  spec.tvos.deployment_target = '10.0'
  spec.watchos.deployment_target = '2.0'

end
