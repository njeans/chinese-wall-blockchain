package main

func contains( list []string, a string) bool {
    for _, b := range list {
        if b == a {
            return true
        }
    }
    return false
}

func containsb( list [][]byte, a []byte) bool {
    for _, b := range list {
        if equal(a, b){
            return true
        }
    }
    return false
}

func equal(a, b []byte) bool {
    if len(a) != len(b) {
        return false
    }
    for i, v := range a {
        if v != b[i] {
            return false
        }
    }
    return true
}
