package test

class Role {

	String authority

	static mapping = {
		autoImport false
		cache true
	}

	static constraints = {
		authority blank: false, unique: true
	}
}
