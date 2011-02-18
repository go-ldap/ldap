package ldap

import (
   "github.com/mmitton/asn1-ber"
   "testing"
)

type compile_test struct {
   filter_str string
   filter_type int
}


var test_filters = []compile_test {
   compile_test{ filter_str: "(&(sn=Miller)(givenName=Bob))", filter_type: FilterAnd },
   compile_test{ filter_str: "(|(sn=Miller)(givenName=Bob))", filter_type: FilterOr },
   compile_test{ filter_str: "(!(sn=Miller))", filter_type: FilterNot },
   compile_test{ filter_str: "(sn=Miller)", filter_type: FilterEqualityMatch },
   compile_test{ filter_str: "(sn=Mill*)", filter_type: FilterSubstrings },
   compile_test{ filter_str: "(sn=*Mill)", filter_type: FilterSubstrings },
   compile_test{ filter_str: "(sn=*Mill*)", filter_type: FilterSubstrings },
   compile_test{ filter_str: "(sn>=Miller)", filter_type: FilterGreaterOrEqual },
   compile_test{ filter_str: "(sn<=Miller)", filter_type: FilterLessOrEqual },
   compile_test{ filter_str: "(sn=*)", filter_type: FilterPresent },
   compile_test{ filter_str: "(sn~=Miller)", filter_type: FilterApproxMatch },
   // compile_test{ filter_str: "()", filter_type: FilterExtensibleMatch },
}

func TestFilter( t *testing.T ) {
   // Test Compiler and Decompiler
   for _, i := range test_filters {
      filter, err := CompileFilter( i.filter_str )
      if err != nil {
         t.Errorf( "Problem compiling %s - %s", err.String() )
      } else if filter.Tag != uint8(i.filter_type) {
         t.Errorf( "%q Expected %q got %q", i.filter_str, FilterMap[ uint64(i.filter_type) ], FilterMap[ uint64(filter.Tag) ] )
      } else {
         o, err := DecompileFilter( filter )
         if err != nil {
            t.Errorf( "Problem compiling %s - %s", i, err.String() )
         } else if i.filter_str != o {
            t.Errorf( "%q expected, got %q", i.filter_str, o )
         }
      }
   }
}

func BenchmarkFilterCompile( b *testing.B ) {
   b.StopTimer()
   filters := make([]string, len( test_filters ) )

   // Test Compiler and Decompiler
   for idx, i := range test_filters {
      filters[ idx ] = i.filter_str
   }

   max_idx := len( filters )
   b.StartTimer()
   for i := 0; i < b.N; i++ {
      CompileFilter( filters[ i % max_idx ] )
   }
}

func BenchmarkFilterDecompile( b *testing.B ) {
   b.StopTimer()
   filters := make([]*ber.Packet, len( test_filters ) )

   // Test Compiler and Decompiler
   for idx, i := range test_filters {
      filters[ idx ], _ = CompileFilter( i.filter_str )
   }

   max_idx := len( filters )
   b.StartTimer()
   for i := 0; i < b.N; i++ {
      DecompileFilter( filters[ i % max_idx ] )
   }
}
