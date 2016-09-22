class User < ApplicationRecord
	# We downcase email before saving it
	before_save { self.email = email.downcase }

	# We check email format with this regex
	VALID_EMAIL_REGEX = /\A[\w+\-.]+@[a-z\d\-]+(\.[a-z\d\-]+)*\.[a-z]+\z/i

	# We validates the presence of Name, Email & Password
	validates(:name, presence: true, length: {maximum:50})
	validates :email, presence: true, length: {maximum:255}, 
					  format:{ with:VALID_EMAIL_REGEX },
					  uniqueness: {case_sensitive: false}
	validates :password, presence: true, length:{ minimum: 6 }

	# methods to set and authenticate against a BCrypt password.
	# It require password_digest attribute
	has_secure_password

	# Return the hash digest of a given string
	def User.digest(string)
		cost = ActiveModel::SecurePassword.min_cost ? BCrypt::Engine::MIN_COST :
                                                  BCrypt::Engine.cost
    	BCrypt::Password.create(string, cost: cost)
	end
end
