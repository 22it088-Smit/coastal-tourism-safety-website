import mongoose from "mongoose";

const reviewSchema = new mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    rating: {
        type: Number,
        required: true,
        min: 1,
        max: 5
    },
    comment: {
        type: String,
        required: true
    },
    date: {
        type: Date,
        default: Date.now
    }
});

const bookingSchema = new mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    checkIn: {
        type: Date,
        required: true
    },
    checkOut: {
        type: Date,
        required: true
    },
    roomType: {
        type: String,
        required: true
    },
    guests: {
        type: Number,
        required: true
    },
    totalPrice: {
        type: Number,
        required: true
    },
    status: {
        type: String,
        enum: ['pending', 'confirmed', 'cancelled'],
        default: 'pending'
    },
    paymentId: String
});

const hotelSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    location: {
        type: {
            type: String,
            enum: ['Point'],
            default: 'Point'
        },
        coordinates: {
            type: [Number],
            required: true
        }
    },
    address: String,
    distance: Number,
    phone: String,
    website: String,
    photos: [String],
    rating: {
        type: Number,
        min: 0,
        max: 5,
        default: 0
    },
    priceLevel: Number,
    reviews: [reviewSchema],
    bookings: [bookingSchema],
    rooms: [{
        type: {
            type: String,
            required: true
        },
        price: {
            type: Number,
            required: true
        },
        capacity: Number,
        available: {
            type: Number,
            default: 1
        }
    }]
});

hotelSchema.index({ location: '2dsphere' });

export default mongoose.model('Hotel', hotelSchema); 